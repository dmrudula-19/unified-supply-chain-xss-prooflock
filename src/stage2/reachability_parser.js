
const fs = require("fs");
const parser = require("@babel/parser");
const traverse = require("@babel/traverse").default;

const filePath = __dirname + "/reachability_sample.js";
const code = fs.readFileSync(filePath, "utf8");

const ast = parser.parse(code, {
    sourceType: "unambiguous"
});

const functions = new Map();
const taintedGlobals = new Set();
const taintedParameters = new Map();
const callGraph = new Map();
const roots = new Set();
const findings = [];

function isSource(node) {
    return node &&
        node.type === "MemberExpression" &&
        node.object.type === "Identifier" &&
        node.object.name === "location" &&
        node.property.type === "Identifier" &&
        ["search", "hash"].includes(node.property.name);
}

function isTainted(node, parameters = new Set()) {
    if (!node) return false;

    if (node.type === "Identifier") {
        return taintedGlobals.has(node.name) ||
            parameters.has(node.name);
    }

    if (isSource(node)) return true;

    if (node.type === "CallExpression") {
        return node.arguments.some(arg =>
            isTainted(arg, parameters)
        );
    }

    if (node.type === "BinaryExpression" ||
        node.type === "LogicalExpression") {
        return isTainted(node.left, parameters) ||
            isTainted(node.right, parameters);
    }

    if (node.type === "ConditionalExpression") {
        return isTainted(node.test, parameters) ||
            isTainted(node.consequent, parameters) ||
            isTainted(node.alternate, parameters);
    }

    if (node.type === "TemplateLiteral") {
        return node.expressions.some(expr =>
            isTainted(expr, parameters)
        );
    }

    if (node.type === "MemberExpression") {
        return isTainted(node.object, parameters);
    }

    return false;
}

// 1. Collect source variables and function declarations.
traverse(ast, {
    VariableDeclarator(path) {
        if (path.node.id.type === "Identifier" &&
            isSource(path.node.init)) {
            taintedGlobals.add(path.node.id.name);
        }
    },

    FunctionDeclaration(path) {
        const name = path.node.id.name;
        functions.set(name, path.node);
        callGraph.set(name, new Set());
        taintedParameters.set(name, new Set());
    }
});

// 2. Build the call graph and identify top-level calls.
traverse(ast, {
    CallExpression(path) {
        const callee = path.node.callee;

        if (callee.type !== "Identifier") return;

        const calledName = callee.name;
        const parentFunction = path.getFunctionParent();

        if (parentFunction) {
            const callerName = parentFunction.node.id?.name;

            if (callerName && functions.has(callerName) &&
                functions.has(calledName)) {
                callGraph.get(callerName).add(calledName);
            }
        } else if (functions.has(calledName)) {
            roots.add(calledName);
        }
    }
});

// 3. Propagate taint through function arguments.
let changed = true;

while (changed) {
    changed = false;

    for (const [callerName, callerNode] of functions) {
        const callerParams = taintedParameters.get(callerName);

        const temporaryAst = parser.parse(
            "(" + code.slice(
                callerNode.start,
                callerNode.end
            ) + ")"
        );

        traverse(temporaryAst, {
            CallExpression(path) {
                const callee = path.node.callee;

                if (callee.type !== "Identifier" ||
                    !functions.has(callee.name)) return;

                const target = functions.get(callee.name);
                const targetParams =
                    taintedParameters.get(callee.name);

                path.node.arguments.forEach((arg, index) => {
                    const parameter = target.params[index];

                    if (!parameter ||
                        parameter.type !== "Identifier") return;

                    if (isTainted(arg, callerParams) &&
                        !targetParams.has(parameter.name)) {
                        targetParams.add(parameter.name);
                        changed = true;
                    }
                });
            }
        });
    }
}

// 4. Find functions reachable from top-level entry calls.
const reachable = new Set();
const queue = [...roots];

while (queue.length > 0) {
    const current = queue.shift();

    if (reachable.has(current)) continue;

    reachable.add(current);

    for (const next of callGraph.get(current) || []) {
        if (!reachable.has(next)) queue.push(next);
    }
}

// 5. Find tainted data reaching dangerous sinks.
for (const [name, fn] of functions) {
    const parameters = taintedParameters.get(name);

    const temporaryAst = parser.parse(
        "(" + code.slice(fn.start, fn.end) + ")"
    );

    traverse(temporaryAst, {
        AssignmentExpression(path) {
            const left = path.node.left;
            const right = path.node.right;

            if (left.type === "MemberExpression" &&
                left.property.type === "Identifier" &&
                ["innerHTML", "outerHTML"].includes(
                    left.property.name
                ) &&
                isTainted(right, parameters)) {

                findings.push({
                    function: name,
                    sink: left.property.name,
                    line: path.node.loc?.start.line,
                    reachable: reachable.has(name)
                });
            }
        },

        CallExpression(path) {
            const callee = path.node.callee;

            if (callee.type === "Identifier" &&
                callee.name === "eval" &&
                path.node.arguments.some(arg =>
                    isTainted(arg, parameters)
                )) {

                findings.push({
                    function: name,
                    sink: "eval()",
                    line: path.node.loc?.start.line,
                    reachable: reachable.has(name)
                });
            }
        }
    });
}

// 6. Print results.
console.log("\nCALL-GRAPH REACHABILITY ANALYSIS");
console.log("----------------------------------");

console.log("Entry points:", [...roots].join(", ") || "None");

console.log("\nCALL GRAPH:");

for (const [name, calls] of callGraph) {
    console.log(name + " -> " +
        ([...calls].join(", ") || "No function calls"));
}

console.log("\nDANGEROUS DATA-FLOW FINDINGS:");

if (findings.length === 0) {
    console.log("No tainted data flows to supported sinks.");
}

for (const finding of findings) {
    let classification;

    if (finding.reachable) {
        classification = "CONFIRMED REACHABLE";
    } else {
        classification = "UNREACHABLE FROM DETECTED ENTRY POINTS";
    }

    console.log("----------------------------------");
    console.log("Function:", finding.function);
    console.log("Dangerous Sink:", finding.sink);
    console.log("Line:", finding.line);
    console.log("Classification:", classification);
}

console.log("----------------------------------");
console.log("Total findings:", findings.length);
console.log("Reachable functions:", [...reachable].join(", ") || "None");
