"""Attack path visualization for awsProwl."""

from __future__ import annotations

from dataclasses import dataclass, field

from awsprowl.core.logging import get_logger

log = get_logger(__name__)


@dataclass
class AttackNode:
    """Node in an attack path graph."""

    id: str
    type: str  # resource, identity, permission, service
    label: str
    arn: str = ""
    properties: dict = field(default_factory=dict)
    risk_score: float = 0.0


@dataclass
class AttackEdge:
    """Edge in an attack path graph."""

    source: str
    target: str
    relationship: str  # allows, assumes, passes, attaches, etc.
    permissions: list[str] = field(default_factory=list)
    confidence: str = "high"


@dataclass
class AttackPath:
    """Complete attack path from source to target."""

    path_id: str
    source_node: AttackNode
    target_node: AttackNode
    intermediate_nodes: list[AttackNode] = field(default_factory=list)
    edges: list[AttackEdge] = field(default_factory=list)
    total_risk: float = 0.0
    techniques: list[str] = field(default_factory=list)
    description: str = ""


class AttackPathBuilder:
    """Builds attack paths from scan findings and resource relationships."""

    def __init__(self):
        self.nodes: dict[str, AttackNode] = {}
        self.edges: list[AttackEdge] = []

    def add_resource_node(self, resource_type: str, resource_id: str, resource_name: str = "",
                          arn: str = "", properties: dict | None = None) -> AttackNode:
        """Add a resource node."""
        node_id = f"{resource_type}:{resource_id}"
        if node_id not in self.nodes:
            self.nodes[node_id] = AttackNode(
                id=node_id,
                type="resource",
                label=resource_name or resource_id,
                arn=arn,
                properties=properties or {},
            )
        return self.nodes[node_id]

    def add_identity_node(self, identity_type: str, identity_id: str, arn: str = "",
                          properties: dict | None = None) -> AttackNode:
        """Add an identity node (user, role, group)."""
        node_id = f"{identity_type}:{identity_id}"
        if node_id not in self.nodes:
            self.nodes[node_id] = AttackNode(
                id=node_id,
                type="identity",
                label=identity_id,
                arn=arn,
                properties=properties or {},
            )
        return self.nodes[node_id]

    def add_permission_edge(self, source_id: str, target_id: str, permissions: list[str],
                            relationship: str = "allows") -> None:
        """Add a permission edge between nodes."""
        edge = AttackEdge(
            source=source_id,
            target=target_id,
            relationship=relationship,
            permissions=permissions,
        )
        self.edges.append(edge)

    def add_trust_edge(self, source_id: str, target_id: str) -> None:
        """Add a trust relationship edge (role assumption)."""
        edge = AttackEdge(
            source=source_id,
            target=target_id,
            relationship="trusts",
            permissions=["sts:AssumeRole"],
        )
        self.edges.append(edge)

    def add_pass_role_edge(self, source_id: str, target_id: str) -> None:
        """Add a PassRole edge."""
        edge = AttackEdge(
            source=source_id,
            target=target_id,
            relationship="passes",
            permissions=["iam:PassRole"],
        )
        self.edges.append(edge)

    def build_from_findings(self, findings: list, resources: dict) -> list[AttackPath]:
        """Build attack paths from findings and resource data."""
        # Clear previous state
        self.nodes.clear()
        self.edges.clear()

        # Add identity nodes from IAM findings
        for finding in findings:
            if finding.get("resource_type") in ("iam_user", "iam_role", "iam_group"):
                self.add_identity_node(
                    finding["resource_type"],
                    finding["resource_id"],
                    finding.get("resource_arn", ""),
                    {"severity": finding.get("severity", "info")}
                )

            # Add resource nodes
            if finding.get("resource_type") not in ("iam_user", "iam_role", "iam_group", "iam_policy"):
                self.add_resource_node(
                    finding["resource_type"],
                    finding["resource_id"],
                    finding.get("resource_name", ""),
                    finding.get("resource_arn", ""),
                    {"severity": finding.get("severity", "info")}
                )

        # Add edges from resource relationships
        self._add_resource_relationships(resources)

        # Find attack paths
        return self._find_attack_paths()

    def _add_resource_relationships(self, resources: dict) -> None:
        """Add edges based on known AWS resource relationships."""
        # This would be populated from actual AWS API calls
        # For now, we add common patterns based on findings
        pass

    def _find_attack_paths(self) -> list[AttackPath]:
        """Find attack paths in the graph using graph traversal."""
        paths = []

        # Find all identity nodes (potential sources)
        identity_nodes = [n for n in self.nodes.values() if n.type == "identity"]

        # Find high-value targets (admin roles, sensitive resources)
        target_nodes = [n for n in self.nodes.values()
                        if n.type == "resource" and n.properties.get("severity") in ("critical", "high")]

        # Simple path finding - in practice would use networkx or similar
        for source in identity_nodes:
            for target in target_nodes:
                path = self._find_path(source.id, target.id)
                if path:
                    paths.append(path)

        return paths

    def _find_path(self, source_id: str, target_id: str, max_depth: int = 5) -> AttackPath | None:
        """Find a path between two nodes using BFS."""
        from collections import deque

        # Build adjacency list
        adj = {}
        for edge in self.edges:
            if edge.source not in adj:
                adj[edge.source] = []
            adj[edge.source].append((edge.target, edge))

        # BFS
        queue = deque([(source_id, [source_id], [])])
        visited = set([source_id])

        while queue:
            current, node_path, edge_path = queue.popleft()

            if current == target_id:
                # Build attack path
                return self._build_attack_path(node_path, edge_path)

            if len(node_path) >= max_depth:
                continue

            for neighbor, edge in adj.get(current, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, node_path + [neighbor], edge_path + [edge]))

        return None

    def _build_attack_path(self, node_ids: list[str], edges: list[AttackEdge]) -> AttackPath:
        """Build an AttackPath object from node IDs and edges."""
        nodes = [self.nodes[nid] for nid in node_ids]
        source = nodes[0]
        target = nodes[-1]
        intermediate = nodes[1:-1]

        techniques = []
        for edge in edges:
            techniques.extend(edge.permissions)

        # Calculate risk score
        total_risk = sum(n.risk_score for n in nodes)
        for edge in edges:
            if "admin" in edge.permissions or "*" in edge.permissions:
                total_risk += 10
            elif "write" in str(edge.permissions).lower():
                total_risk += 5
            else:
                total_risk += 1

        return AttackPath(
            path_id=f"path-{hash(tuple(node_ids))}",
            source_node=source,
            target_node=target,
            intermediate_nodes=intermediate,
            edges=edges,
            total_risk=total_risk,
            techniques=list(set(techniques)),
            description=self._generate_path_description(source, target, edges),
        )

    def _generate_path_description(self, source: AttackNode, target: AttackNode,
                                    edges: list[AttackEdge]) -> str:
        """Generate human-readable description of attack path."""
        steps = []
        for edge in edges:
            if edge.relationship == "allows":
                steps.append(f"{edge.source} allows {', '.join(edge.permissions)} on {edge.target}")
            elif edge.relationship == "trusts":
                steps.append(f"{edge.source} can be assumed by {edge.target}")
            elif edge.relationship == "passes":
                steps.append(f"{edge.source} can pass role {edge.target}")

        return f"Attack path from {source.label} to {target.label}: {' -> '.join(steps)}"

    def to_graph_dict(self) -> dict:
        """Export graph as dictionary for visualization."""
        return {
            "nodes": [
                {
                    "id": node.id,
                    "type": node.type,
                    "label": node.label,
                    "arn": node.arn,
                    "properties": node.properties,
                    "risk_score": node.risk_score,
                }
                for node in self.nodes.values()
            ],
            "edges": [
                {
                    "source": edge.source,
                    "target": edge.target,
                    "relationship": edge.relationship,
                    "permissions": edge.permissions,
                    "confidence": edge.confidence,
                }
                for edge in self.edges
            ],
        }

    def to_cytoscape_json(self) -> dict:
        """Export graph in Cytoscape.js format for web visualization."""
        elements = []

        for node in self.nodes.values():
            color = self._get_node_color(node)
            elements.append({
                "data": {
                    "id": node.id,
                    "label": node.label,
                    "type": node.type,
                    "arn": node.arn,
                    "risk_score": node.risk_score,
                    "color": color,
                },
                "classes": node.type,
            })

        for edge in self.edges:
            elements.append({
                "data": {
                    "id": f"{edge.source}->{edge.target}",
                    "source": edge.source,
                    "target": edge.target,
                    "relationship": edge.relationship,
                    "permissions": ", ".join(edge.permissions),
                },
                "classes": edge.relationship,
            })

        return {"elements": elements}

    def _get_node_color(self, node: AttackNode) -> str:
        """Get color for node based on risk."""
        if node.risk_score >= 20:
            return "#ff0000"  # Critical - red
        if node.risk_score >= 10:
            return "#ff8800"  # High - orange
        if node.risk_score >= 5:
            return "#ffcc00"  # Medium - yellow
        return "#00aa00"  # Low - green


def create_attack_path_builder() -> AttackPathBuilder:
    """Create an attack path builder."""
    return AttackPathBuilder()
