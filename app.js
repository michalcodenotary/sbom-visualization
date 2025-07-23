document.addEventListener('DOMContentLoaded', () => {
    // --- DOM Elements ---
    const fileInput = document.getElementById('sbom-file-input');
    const clearBtn = document.getElementById('clear-btn');
    const graphContainer = document.getElementById('graph-container');
    const statusContainer = document.getElementById('status-container');
    const exampleButtonsContainer = document.getElementById('example-buttons-container');

    // --- Graph State ---
    let nodes = new vis.DataSet();
    let edges = new vis.DataSet();
    let dependencyMap = {};
    let componentOrigins = {};
    const network = new vis.Network(graphContainer, { nodes, edges }, {
        layout: { hierarchical: { enabled: true, direction: 'UD', sortMethod: 'directed' } },
        nodes: { shape: 'box' },
        edges: { smooth: true, arrows: { to: { enabled: true, scaleFactor: 1 } } },
        groups: {
            dangling: { color: { border: '#95a5a6', background: '#ecf0f1' }, shape: 'ellipse' },
            root: { color: { border: '#27ae60', background: '#d5f5e3' } }
        }
    });

    // --- Initialization ---
    loadExampleManifest();

    // --- Event Handlers ---
    fileInput.addEventListener('change', (event) => {
        const file = event.target.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = (e) => {
            try {
                const sbom = JSON.parse(e.target.result);
                processSbom(sbom, file.name);
            } catch (err) {
                showError(`Error parsing ${file.name}. Not a valid JSON file.`);
            }
        };
        reader.readAsText(file);
        fileInput.value = '';
    });

    clearBtn.addEventListener('click', () => {
        nodes.clear();
        edges.clear();
        dependencyMap = {};
        componentOrigins = {};
        clearStatus();
    });

    // --- Dynamic Example Loading ---
    async function loadExampleManifest() {
        try {
            const response = await fetch('./examples/manifest.json');
            if (!response.ok) throw new Error('manifest.json not found.');
            const manifest = await response.json();

            for (const example of manifest.examples) {
                const buttonContainer = document.createElement('div');
                buttonContainer.className = 'tooltip';

                const button = document.createElement('button');
                button.textContent = example.name;
                button.onclick = async () => {
                    try {
                        const res = await fetch(`./examples/${example.file}`);
                        const sbom = await res.json();
                        processSbom(sbom, example.file);
                    } catch (err) {
                        showError(`Could not load or parse ${example.file}.`);
                    }
                };

                const tooltipText = document.createElement('span');
                tooltipText.className = 'tooltip-text';
                const pre = document.createElement('pre');
                pre.textContent = 'Loading...';
                tooltipText.appendChild(pre);

                buttonContainer.appendChild(button);
                buttonContainer.appendChild(tooltipText);
                exampleButtonsContainer.appendChild(buttonContainer);

                // Pre-fetch content for tooltip on hover
                buttonContainer.addEventListener('mouseenter', async () => {
                    if (pre.textContent === 'Loading...') {
                        try {
                            const res = await fetch(`./examples/${example.file}`);
                            const text = await res.text();
                            pre.textContent = text;
                        } catch {
                            pre.textContent = 'Could not load content.';
                        }
                    }
                }, { once: true }); // Only fetch once
            }
        } catch (error) {
            showError("Could not load example manifest. Make sure /examples/manifest.json exists.");
        }
    }

    // --- UI Feedback ---
    function showStatus(message) { statusContainer.innerHTML = `<div class="status-message status-success">${message}</div>`; }
    function showError(message) { statusContainer.innerHTML = `<div class="status-message status-error">${message}</div>`; }
    function clearStatus() { statusContainer.innerHTML = ''; }

    // --- Core Processing Logic ---
    function processSbom(sbom, sourceName) {
        // 1. Create a temporary, future state of the dependency map
        const tempDependencyMap = JSON.parse(JSON.stringify(dependencyMap)); // Deep clone
        if (sbom.dependencies) {
            const fileDeps = {};
            sbom.dependencies.forEach(dep => {
                if (!fileDeps[dep.ref]) fileDeps[dep.ref] = [];
                fileDeps[dep.ref].push(...(dep.dependsOn || []));
            });
            Object.assign(tempDependencyMap, fileDeps); // Overwrite with new dependencies
        }

        // 2. Validate the future state for circular dependencies
        if (hasCycle(tempDependencyMap)) {
            showError(`Error: Loading '${sourceName}' would create a circular dependency. Operation cancelled.`);
            return; // ABORT!
        }

        // 3. If validation passes, commit the changes to the actual state
        dependencyMap = tempDependencyMap;

        // 4. Add new nodes to the graph
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

        // 5. Rebuild the entire graph from the new state
        rebuildGraph();
        showStatus(`Successfully processed ${sourceName}.`);
    }

    function rebuildGraph() {
        edges.clear();

        const newEdges = [];
        const allDependencies = new Set();
        Object.values(dependencyMap).forEach(deps => deps.forEach(dep => allDependencies.add(dep)));

        for (const ref in dependencyMap) {
            dependencyMap[ref].forEach(dep => newEdges.push({ from: ref, to: dep }));
        }
        edges.update(newEdges);

        // Identify and style dangling nodes
        const allNodeIds = nodes.getIds();
        const updatedNodes = [];
        allNodeIds.forEach(nodeId => {
            const isDependedOn = allDependencies.has(nodeId);
            const hasDependencies = dependencyMap[nodeId] && dependencyMap[nodeId].length > 0;
            const isRoot = componentOrigins[nodeId];
            const currentNode = nodes.get(nodeId);

            if (!isRoot && !isDependedOn && !hasDependencies) {
                updatedNodes.push({ id: nodeId, group: 'dangling' });
            } else if (currentNode && currentNode.group === 'dangling') {
                updatedNodes.push({ id: nodeId, group: isRoot ? 'root' : null });
            }
        });
        if(updatedNodes.length > 0) nodes.update(updatedNodes);
    }

    function hasCycle(graph) {
        const visited = new Set();
        const recursionStack = new Set();
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