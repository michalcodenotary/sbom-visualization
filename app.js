document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements
    const fileInput = document.getElementById('sbom-file-input');
    const clearBtn = document.getElementById('clear-btn');
    const graphContainer = document.getElementById('graph-container');
    const statusMessage = document.getElementById('status-message');
    const exampleButtonsContainer = document.getElementById('example-buttons-container');

    // Graph State
    const nodes = new vis.DataSet();
    const edges = new vis.DataSet();
    let dependencyMap = {}; // Tracks all dependencies: { "ref": ["dependsOn", ...] }
    let componentOrigins = {}; // Tracks the root components from metadata

    // vis-network setup
    const graphData = { nodes, edges };
    const options = {
        layout: { hierarchical: { enabled: true, direction: 'UD', sortMethod: 'directed', nodeSpacing: 150, treeSpacing: 200,}, },
        nodes: { shape: 'box', font: { size: 14 }, borderWidth: 2, color: { border: '#3498db', background: '#d2e9fc', highlight: { border: '#2980b9', background: '#eaf4fd' }, }, },
        edges: { smooth: true, arrows: { to: { enabled: true, scaleFactor: 1 } }, },
        groups: {
            dangling: { color: { border: '#95a5a6', background: '#ecf0f1' }, shape: 'ellipse',},
            root: { color: { border: '#27ae60', background: '#d5f5e3' }, }
        },
        physics: { enabled: false,},
    };
    const network = new vis.Network(graphContainer, graphData, options);

    // --- Initialization ---
    loadExampleManifest();

    // --- Event Handlers ---
    fileInput.addEventListener('change', (event) => {
        const file = event.target.files[0];
        if (file) {
            const reader = new FileReader();
            reader.onload = (e) => {
                try {
                    const sbom = JSON.parse(e.target.result);
                    processSbom(sbom, file.name);
                } catch (err) {
                    statusMessage.textContent = `Error parsing ${file.name}. Is it a valid JSON?`;
                }
            };
            reader.readAsText(file);
        }
        fileInput.value = ''; // Reset input
    });

    async function handleExampleClick(event) {
        const filename = event.target.dataset.exampleFile;
        const path = `./examples/${filename}`;
        try {
            const response = await fetch(path);
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            const sbom = await response.json();
            processSbom(sbom, filename);
        } catch (err) {
            statusMessage.textContent = `Error loading example ${filename}.`;
            console.error(err);
        }
    }

    clearBtn.addEventListener('click', () => {
        nodes.clear();
        edges.clear();
        dependencyMap = {};
        componentOrigins = {};
        statusMessage.textContent = 'Graph cleared.';
    });

    // --- Dynamic Loading ---
    async function loadExampleManifest() {
        try {
            const response = await fetch('./examples/manifest.json');
            if (!response.ok) throw new Error('manifest.json not found.');
            const manifest = await response.json();

            manifest.examples.forEach(example => {
                const button = document.createElement('button');
                button.textContent = example.name;
                button.dataset.exampleFile = example.file;
                button.addEventListener('click', handleExampleClick);
                exampleButtonsContainer.appendChild(button);
            });

        } catch (error) {
            console.error("Could not load example manifest:", error);
            statusMessage.textContent = 'Could not load examples.';
        }
    }

    // --- Core Logic ---
    function processSbom(sbom, sourceName) {
        const newNodes = [];
        if (sbom.metadata && sbom.metadata.component) {
            const rootPurl = sbom.metadata.component.purl;
            newNodes.push({ id: rootPurl, label: rootPurl.split('@')[0], group: 'root' });
            componentOrigins[rootPurl] = true;
        }
        if (sbom.components) {
            sbom.components.forEach(c => newNodes.push({ id: c.purl, label: c.purl.split('@')[0] }));
        }
        nodes.update(newNodes);

        if (sbom.dependencies) {
            const fileDependencyMap = {};
            sbom.dependencies.forEach(dep => {
                if (!fileDependencyMap[dep.ref]) fileDependencyMap[dep.ref] = [];
                fileDependencyMap[dep.ref].push(...(dep.dependsOn || []));
            });
            Object.assign(dependencyMap, fileDependencyMap);
        }

        if (hasCycle(dependencyMap)) {
            statusMessage.textContent = "Error: Circular dependency detected! Graph update cancelled.";
            return;
        }

        rebuildGraph();
        statusMessage.textContent = `Processed ${sourceName}.`;
    }

    function rebuildGraph() {
        edges.clear();

        const newEdges = [];
        const allDependencies = new Set();
        Object.values(dependencyMap).forEach(deps => deps.forEach(dep => allDependencies.add(dep)));

        for (const ref in dependencyMap) {
            dependencyMap[ref].forEach(dep => newEdges.push({ from: ref, to: dep }));
        }
        edges.add(newEdges);

        const allNodeIds = nodes.getIds();
        const updatedNodes = [];
        allNodeIds.forEach(nodeId => {
            const isDependedOn = allDependencies.has(nodeId);
            const hasDependencies = dependencyMap[nodeId] && dependencyMap[nodeId].length > 0;
            const isRoot = componentOrigins[nodeId];

            if (!isRoot && !isDependedOn && !hasDependencies) {
                updatedNodes.push({ id: nodeId, group: 'dangling' });
            } else {
                const currentNode = nodes.get(nodeId);
                if(currentNode.group === 'dangling') {
                    updatedNodes.push({ id: nodeId, group: isRoot ? 'root' : null });
                }
            }
        });

        if(updatedNodes.length > 0) nodes.update(updatedNodes);
    }

    function hasCycle(graph) {
        const visited = new Set(), recursionStack = new Set();
        function detect(node) {
            visited.add(node);
            recursionStack.add(node);
            const neighbors = graph[node] || [];
            for (const neighbor of neighbors) {
                if (!visited.has(neighbor)) {
                    if (detect(neighbor)) return true;
                } else if (recursionStack.has(neighbor)) {
                    return true;
                }
            }
            recursionStack.delete(node);
            return false;
        }
        for (const node in graph) {
            if (!visited.has(node)) if (detect(node)) return true;
        }
        return false;
    }
});