
const fs = require("fs");
const path = require("path");
const parser = require("@babel/parser");
const traverse = require("@babel/traverse").default;

const inputPath = path.join(__dirname, "branch_sample.js");
const outputPath = path.join(__dirname, "security_report.json");

const code = fs.readFileSync(inputPath, "utf8");

const ast = parser.parse(code, {
    sourceType: "unambiguous"
});

const findings = [];
const allTaintedVariables = new Set();

function getSource(node) {
    if (!node || node.type !== "MemberExpression") {
        return null;
    }

    const object = node.object;
    const property = node.property;

    if (
        object.type === "Identifier" &&
        object.name === "location" &&
        !node.computed &&
        property.type === "Identifier"
    ) {
        if (property.name === "search") return "location.search";
        if (property.name === "hash") return "location.hash";
    }

    return null;
}

function getSources(node, state) {
    const sources = new Set();

    if (!node) return sources;

    const directSource = getSource(node);

    if (directSource) {
        sources.add(directSource);
        return sources;
    }

    if (node.type === "Identifier") {
        const stored = state.get(node.name);

        if (stored) {
            stored.forEach(source => sources.add(source));
        }
    }

    if (node.type === "BinaryExpression" ||
        node.type === "LogicalExpression") {
        getSources(node.left, state).forEach(s => sources.add(s));
        getSources(node.right, state).forEach(s => sources.add(s));
    }

    if (node.type === "ConditionalExpression") {
        getSources(node.test, state).forEach(s => sources.add(s));
        getSources(node.consequent, state).forEach(s => sources.add(s));
        getSources(node.alternate, state).forEach(s => sources.add(s));
    }

    if (node.type === "TemplateLiteral") {
        node.expressions.forEach(expression => {
            getSources(expression, state).forEach(s => sources.add(s));
        });
    }

    if (node.type === "CallExpression") {
        node.arguments.forEach(argument => {
            getSources(argument, state).forEach(s => sources.add(s));
        });
    }

    if (node.type === "ArrayExpression") {
        node.elements.forEach(element => {
            getSources(element, state).forEach(s => sources.add(s));
        });
    }

    if (node.type === "ObjectExpression") {
        node.properties.forEach(property => {
            if (property.type === "ObjectProperty") {
                getSources(property.value, state)
                    .forEach(s => sources.add(s));
            }
        });
    }

    return sources;
}

function addFinding(sink, line, sources) {
    if (sources.size === 0) return;

    const existing = findings.find(
        finding => finding.sink === sink && finding.line === line
    );

    if (existing) {
        sources.forEach(source => existing.sources.add(source));
        return;
    }

    findings.push({
        sink,
        line,
        sources: new Set(sources)
    });
}

function detectSink(node, state) {
    if (!node) return;

    if (node.type === "AssignmentExpression") {
        const left = node.left;
        let sink = null;

        if (left.type === "MemberExpression" &&
            left.property.type === "Identifier") {

            if (left.property.name === "innerHTML") {
                sink = "innerHTML";
            }

            if (left.property.name === "outerHTML") {
                sink = "outerHTML";
            }
        }

        if (sink) {
            const sources = getSources(node.right, state);
            addFinding(sink, node.loc.start.line, sources);
        }
    }

    if (node.type === "CallExpression") {
        let sink = null;

        if (node.callee.type === "Identifier" &&
            node.callee.name === "eval") {
            sink = "eval()";
        }

        if (node.callee.type === "MemberExpression" &&
            node.callee.object.type === "Identifier" &&
            node.callee.object.name === "document" &&
            node.callee.property.type === "Identifier" &&
            node.callee.property.name === "write") {
            sink = "document.write()";
        }

        if (sink && node.arguments.length > 0) {
            const sources = getSources(node.arguments[0], state);
            addFinding(sink, node.loc.start.line, sources);
        }
    }
}

function cloneState(state) {
    const copy = new Map();

    state.forEach((sources, variable) => {
        copy.set(variable, new Set(sources));
    });

    return copy;
}

function mergeStates(state1, state2) {
    const merged = cloneState(state1);

    state2.forEach((sources, variable) => {
        if (!merged.has(variable)) {
            merged.set(variable, new Set());
        }

        sources.forEach(source => {
            merged.get(variable).add(source);
        });
    });

    return merged;
}

function analyzeExpression(node, state) {
    if (!node) return;

    detectSink(node, state);

    if (node.type === "AssignmentExpression") {
        if (node.left.type === "Identifier") {
            const sources = getSources(node.right, state);

            if (sources.size > 0) {
                state.set(node.left.name, sources);
                allTaintedVariables.add(node.left.name);
            } else {
                state.delete(node.left.name);
            }
        }
    }
}

function analyzeStatements(statements, initialState) {
    let state = cloneState(initialState);

    for (const statement of statements) {

        if (statement.type === "VariableDeclaration") {
            for (const declaration of statement.declarations) {
                if (declaration.id.type !== "Identifier") continue;

                const variable = declaration.id.name;
                const sources = getSources(declaration.init, state);

                if (sources.size > 0) {
                    state.set(variable, sources);
                    allTaintedVariables.add(variable);
                } else {
                    state.delete(variable);
                }

                if (declaration.init) {
                    detectSink(declaration.init, state);
                }
            }
        }

        else if (statement.type === "ExpressionStatement") {
            analyzeExpression(statement.expression, state);
        }

        else if (statement.type === "IfStatement") {
            const consequentState = analyzeStatements(
                statement.consequent.type === "BlockStatement"
                    ? statement.consequent.body
                    : [statement.consequent],
                state
            );

            const alternateState = statement.alternate
                ? analyzeStatements(
                    statement.alternate.type === "BlockStatement"
                        ? statement.alternate.body
                        : [statement.alternate],
                    state
                )
                : cloneState(state);

            state = mergeStates(consequentState, alternateState);
        }
    }

    return state;
}

const finalState = analyzeStatements(ast.program.body, new Map());

console.log("\nPROOFLOCK - SOURCE-AWARE BRANCH TAINT ANALYSIS");
console.log("----------------------------------");

console.log(
    "Tainted variables: " +
    Array.from(allTaintedVariables).join(", ")
);

console.log("\nDANGEROUS DATA-FLOW FINDINGS:");
console.log("----------------------------------");

findings.forEach((finding, index) => {
    console.log(`Finding: ${index + 1}`);
    console.log(`Finding ID: PL-${String(index + 1).padStart(3, "0")}`);
    console.log(`Dangerous Sink: ${finding.sink}`);
    console.log(`Source: ${Array.from(finding.sources).join(", ")}`);
    console.log("Classification: POTENTIALLY REACHABLE");
    console.log(`Line: ${finding.line}`);
    console.log("----------------------------------");
});

console.log(`Total dangerous flows: ${findings.length}`);

const report = {
    project: "ProofLock",
    version: "1.1",
    analysis_type: "Source-Aware Branch Taint Analysis",
    generated_at: new Date().toISOString(),
    total_findings: findings.length,

    findings: findings.map((finding, index) => {
        const sources = Array.from(finding.sources);

        return {
            finding_id: `PL-${String(index + 1).padStart(3, "0")}`,
            vulnerability: finding.sink,
            severity: "HIGH",

            source: {
                types: sources,
                description: "Untrusted input from browser URL"
            },

            sink: {
                type: finding.sink,
                file: path.basename(inputPath),
                line: finding.line
            },

            classification: "POTENTIALLY_REACHABLE",
            confidence: "MEDIUM",
            source_to_sink: "DETECTED",
            verification_status: "PENDING_DYNAMIC_VERIFICATION"
        };
    })
};

fs.writeFileSync(
    outputPath,
    JSON.stringify(report, null, 4)
);

console.log("\nADVANCED SECURITY REPORT");
console.log("----------------------------------");
console.log("Project: ProofLock");
console.log(`Total findings: ${findings.length}`);
console.log(`Report saved to: ${outputPath}`);
