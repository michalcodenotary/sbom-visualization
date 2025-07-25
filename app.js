document.addEventListener('DOMContentLoaded', () => {
    // --- DOM Elements ---
    const fileInput = document.getElementById('sbom-file-input');
    const clearBtn = document.getElementById('clear-btn');
    const graphContainer = document.getElementById('graph-container');
    const statusContainer = document.getElementById('status-container');
    const exampleButtonsContainer = document.getElementById('example-buttons-container');
    const modal = document.getElementById('file-viewer-modal');
    const modalTitle = document.getElementById('modal-title');
    const closeModalBtn = document.getElementById('close-modal-btn');
    const fileContentPre = document.getElementById('file-content-pre');
    
    // File preview elements
    const filePreviewSection = document.getElementById('file-preview-section');
    const filePreviewTitle = document.getElementById('file-preview-title');
    const filePreviewContent = document.getElementById('file-preview-content');
    const closePreviewBtn = document.getElementById('close-preview-btn');

    // --- Graph State & Setup ---
    let nodes = new vis.DataSet();
    let edges = new vis.DataSet();
    let dependencyMap = {};
    let componentOrigins = {};
    const network = new vis.Network(graphContainer, { nodes, edges }, {
        layout: { hierarchical: { enabled: true, direction: 'UD', sortMethod: 'directed' } },
        nodes: { shape: 'box' },
        edges: { smooth: true, arrows: { to: { enabled: true, scaleFactor: 1 } } },
        groups: {
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
            } catch (err) { showError(`Error parsing ${file.name}. Not a valid JSON file.`); }
        };
        reader.readAsText(file);
        fileInput.value = '';
    });

    clearBtn.addEventListener('click', () => {
        nodes.clear(); edges.clear();
        dependencyMap = {}; componentOrigins = {};
        clearStatus();
    });

    // Modal close events
    closeModalBtn.addEventListener('click', () => modal.style.display = 'none');
    window.addEventListener('click', (event) => {
        if (event.target === modal) modal.style.display = 'none';
    });
    
    // File preview close event
    closePreviewBtn.addEventListener('click', () => {
        filePreviewSection.style.display = 'none';
    });

    // --- Dynamic Example Loading ---
    async function loadExampleManifest() {
        try {
            const response = await fetch('./examples/manifest.json');
            if (!response.ok) throw new Error('manifest.json not found.');
            const manifest = await response.json();

            for (const example of manifest.examples) {
                const itemContainer = document.createElement('div');
                itemContainer.className = 'example-item';

                const nameSpan = document.createElement('span');
                nameSpan.textContent = example.name;

                const viewBtn = document.createElement('a');
                viewBtn.textContent = 'View';
                viewBtn.className = 'button view-btn';
                viewBtn.href = '#';
                viewBtn.onclick = async (e) => {
                    e.preventDefault();
                    try {
                        const res = await fetch(`./examples/${example.file}`);
                        const text = await res.text();
                        showFilePreview(example.file, text);
                    } catch { showError(`Could not load content for ${example.file}.`); }
                };

                const loadBtn = document.createElement('button');
                loadBtn.textContent = 'Load';
                loadBtn.onclick = async () => {
                    try {
                        const res = await fetch(`./examples/${example.file}`);
                        const sbom = await res.json();
                        processSbom(sbom, example.file);
                    } catch (err) { 
                        console.error(`Error loading ${example.file}:`, err);
                        showError(`Could not load or parse ${example.file}. Error: ${err.message}`); 
                    }
                };

                itemContainer.appendChild(nameSpan);
                itemContainer.appendChild(viewBtn);
                itemContainer.appendChild(loadBtn);
                exampleButtonsContainer.appendChild(itemContainer);
            }
        } catch (error) { showError("Could not load examples. Make sure /examples/manifest.json exists."); }
    }

    // --- File Preview Functions ---
    function showFilePreview(filename, content) {
        filePreviewTitle.textContent = filename;
        filePreviewContent.textContent = content;
        filePreviewSection.style.display = 'flex';
    }
    
    // --- UI Feedback & Core Logic (Identical to previous correct version) ---
    function showStatus(message) { statusContainer.innerHTML = `<div class="status-message status-success">${message}</div>`; }
    function showError(message) { statusContainer.innerHTML = `<div class="status-message status-error">${message}</div>`; }
    function clearStatus() { statusContainer.innerHTML = ''; }

function processSbom(sbom, sourceName) {
    // Collect all components mentioned in this file (both root component and listed components)
    const allFileComponents = new Set();
    
    if (sbom.metadata && sbom.metadata.component) {
        allFileComponents.add(sbom.metadata.component.purl);
    }
    if (sbom.components) {
        sbom.components.forEach(c => allFileComponents.add(c.purl));
    }
    
    if (sbom.dependencies) {
        const fileDeps = {};
        sbom.dependencies.forEach(dep => {
            if (!fileDeps[dep.ref]) fileDeps[dep.ref] = [];
            fileDeps[dep.ref].push(...(dep.dependsOn || []));
        });
        
        // Check for self-referential cycles within this file only
        for (const componentRef in fileDeps) {
            if (hasPathToSelf(componentRef, fileDeps, new Set())) {
                showError(`Error: '${sourceName}' contains a self-referential dependency for '${componentRef}'. Operation cancelled.`);
                return;
            }
        }
        
        // Clear dependencies for ALL components mentioned in this file
        allFileComponents.forEach(component => {
            delete dependencyMap[component];
        });
        
        // Set new dependencies only for components that have them defined
        Object.assign(dependencyMap, fileDeps);
    } else {
        // If no dependencies section, clear all dependencies for mentioned components
        allFileComponents.forEach(component => {
            delete dependencyMap[component];
        });
    }

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

    rebuildGraph();
    showStatus(`Successfully processed ${sourceName}.`);
}

    function rebuildGraph() {
        edges.clear();

        const newEdges = [], allDependencies = new Set();
        Object.entries(dependencyMap).forEach(([ref, deps]) => {
            deps.forEach(dep => {
                allDependencies.add(dep);
                newEdges.push({ from: ref, to: dep });
            });
        });
        edges.update(newEdges);

        const allNodeIds = nodes.getIds();
        const updatedNodes = [];
        allNodeIds.forEach(nodeId => {
            const isDependedOn = allDependencies.has(nodeId);
            const hasDependencies = dependencyMap[nodeId] && dependencyMap[nodeId].length > 0;
            const isRoot = componentOrigins[nodeId];
            const currentNode = nodes.get(nodeId);
            
            // Determine what the node's group SHOULD be
            let targetGroup;
            if (isRoot) {
                targetGroup = 'root';
            } else {
                targetGroup = undefined; // Default styling (blue)
            }
            
            // Only update if the group needs to change
            const currentGroup = currentNode ? currentNode.group : undefined;
            if (currentGroup !== targetGroup) {
                const nodeUpdate = { id: nodeId };
                if (targetGroup) {
                    nodeUpdate.group = targetGroup;
                }
                // If targetGroup is undefined, don't set group property
                // This uses default vis.js styling
                updatedNodes.push(nodeUpdate);
            }
        });
        if(updatedNodes.length > 0) nodes.update(updatedNodes);
    }

    // Check if a component has a path back to itself within the same file
    function hasPathToSelf(startNode, fileDeps, visited) {
        if (visited.has(startNode)) return true; // Found a cycle back to start
        
        visited.add(startNode);
        const dependencies = fileDeps[startNode] || [];
        
        for (const dep of dependencies) {
            // Only check dependencies that are defined in this same file
            if (fileDeps.hasOwnProperty(dep)) {
                if (dep === startNode || hasPathToSelf(dep, fileDeps, new Set(visited))) {
                    return true;
                }
            }
        }
        
        return false;
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
                } else if (recursionStack.has(neighbor)) { return true; }
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