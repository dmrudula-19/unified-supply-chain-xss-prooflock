
const fs = require("fs");
const parser = require("@babel/parser");
const traverse = require("@babel/traverse").default;

const filePath = process.argv[2];

if (!filePath) {
    console.log("Usage: node function_parser.js <javascript-file>");
    process.exit(1);
}

const code = fs.readFileSync(filePath, "utf8");

const ast = parser.parse(code, {
    sourceType: "unambiguous"
});

function containsSource(node) {
    if (!node) return false;

    if (node.type === "MemberExpression") {
        const object = node.object;
        const property = node.property;

        if (
            object.type === "Identifier" &&
            object.name === "location" &&
            property.name === "search"
        ) {
            return true;
        }

        if (
            object.type === "Identifier" &&
            object.name === "location" &&
            property.name === "hash"
        ) {
            return true;
        }

        if (
            object.type === "Identifier" &&
            object.name === "document" &&
            property.name === "URL"
        ) {
            return true;
        }

        if (
            object.type === "Identifier" &&
            ["req", "request"].includes(object.name) &&
            ["query", "body", "params"].includes(property.name)
        ) {
            return true;
        }
    }

    return false;
}

function getIdentifiers(node) {
    const names = [];

    if (!node) return names;

    if (node.type === "Identifier") {
        names.push(node.name);
    }

    traverse(
        parser.parse(`(${codeForNode(node)})`, {
            sourceType: "unambiguous"
        }),
        {
            Identifier(path) {
                names.push(path.node.name);
            }
        }
    );

    return names;
}

function codeForNode(node) {
    // Used only as a fallback for identifier collection.
    // The main analysis below uses Babel AST nodes directly.
    return node.type === "Identifier" ? node.name : "";
}

const taintedVariables = new Set();
const functions = new Map();
const findings = [];

function nodeContainsTaintedIdentifier(node, taintedNames) {
    if (!node) return false;

    if (node.type === "Identifier") {
        return taintedNames.has(node.name);
    }

    if (containsSource(node)) {
        return true;
    }

    return false;
}

// Step 1: Identify variables initialized from untrusted sources.
traverse(ast, {
    VariableDeclarator(path) {
        if (
            path.node.id.type === "Identifier" &&
            containsSource(path.node.init)
        ) {
            taintedVariables.add(path.node.id.name);
            console.log(
                "UNTRUSTED SOURCE:",
                path.node.id.name,
                "| Line:",
                path.node.loc.start.line
            );
        }
    }
});

// Step 2: Identify function declarations.
traverse(ast, {
    FunctionDeclaration(path) {
        if (path.node.id) {
            functions.set(path.node.id.name, path.node);
        }
    }
});

// Step 3: Check calls and transfer taint to function parameters.
traverse(ast, {
    CallExpression(path) {
        if (path.node.callee.type !== "Identifier") return;

        const functionName = path.node.callee.name;
        const functionNode = functions.get(functionName);

        if (!functionNode) return;

        const taintedParameters = new Set();

        functionNode.params.forEach((parameter, index) => {
            const argument = path.node.arguments[index];

            if (
                parameter.type === "Identifier" &&
                argument &&
                (
                    containsSource(argument) ||
                    (
                        argument.type === "Identifier" &&
                        taintedVariables.has(argument.name)
                    )
                )
            ) {
                taintedParameters.add(parameter.name);
            }
        });

        if (taintedParameters.size === 0) return;

        // Step 4: Inspect the function body for dangerous sinks.
        const functionCode = code.slice(
            functionNode.body.start,
            functionNode.body.end
        );

        const functionAst = parser.parse(functionCode, {
            sourceType: "unambiguous"
        });

        traverse(functionAst, {
            AssignmentExpression(sinkPath) {
                const left = sinkPath.node.left;
                const right = sinkPath.node.right;

                if (
                    left.type === "MemberExpression" &&
                    left.property.type === "Identifier" &&
                    ["innerHTML", "outerHTML"].includes(left.property.name)
                ) {
                    if (
                        right.type === "Identifier" &&
                        taintedParameters.has(right.name)
                    ) {
                        findings.push({
                            function: functionName,
                            sink: left.property.name,
                            line: functionNode.loc.start.line,
                            parameter: right.name
                        });
                    }
                }
            },

            CallExpression(sinkPath) {
                const call = sinkPath.node;

                if (
                    call.callee.type === "Identifier" &&
                    call.callee.name === "eval"
                ) {
                    const argument = call.arguments[0];

                    if (
                        argument &&
                        argument.type === "Identifier" &&
                        taintedParameters.has(argument.name)
                    ) {
                        findings.push({
                            function: functionName,
                            sink: "eval()",
                            line: functionNode.loc.start.line,
                            parameter: argument.name
                        });
                    }
                }
            }
        });
    }
});

console.log("\nFUNCTION-LEVEL DATA-FLOW ANALYSIS");
console.log("----------------------------------");

if (findings.length === 0) {
    console.log("No function-level source-to-sink flow detected.");
} else {
    findings.forEach((finding) => {
        console.log("Function:", finding.function);
        console.log("Dangerous Sink:", finding.sink);
        console.log("Tainted Parameter:", finding.parameter);
        console.log("Function Line:", finding.line);
        console.log("RESULT: SOURCE TO SINK FLOW DETECTED");
        console.log("----------------------------------");
    });
}

console.log("Total function-level flows:", findings.length);
