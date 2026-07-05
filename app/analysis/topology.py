"""
Graph-invariant feature mining over anchor subgraphs.

Eigenvector and Katz centrality are intentionally NOT computed here by
default — they're expensive on graphs with disconnected components (common
in extracted subgraphs) and will throw or hang on certain topologies.
Degree, closeness, and clustering are the reliable prototype set. Add the
other two only if your demo set specifically needs them and you've tested
they converge on your actual subgraph shapes.
"""
import statistics
import networkx as nx


def _stats(values: list[float]) -> dict[str, float]:
    if not values:
        return {"mean": 0.0, "std": 0.0, "median": 0.0, "min": 0.0, "max": 0.0}
    return {
        "mean": statistics.mean(values),
        "std": statistics.pstdev(values) if len(values) > 1 else 0.0,
        "median": statistics.median(values),
        "min": min(values),
        "max": max(values),
    }


def compute_topological_invariants(g: nx.DiGraph) -> dict[str, float]:
    """
    Computes centrality distributions over a subgraph and flattens them
    into a stats dict suitable for direct inclusion in the feature vector.
    Returns keys like "degree_centrality_mean", "closeness_centrality_std", etc.
    """
    if g.number_of_nodes() == 0:
        empty = _stats([])
        out = {}
        for metric in ["degree_centrality", "closeness_centrality", "clustering_coefficient"]:
            for stat_name, val in empty.items():
                out[f"{metric}_{stat_name}"] = val
        return out

    degree_c = nx.degree_centrality(g)
    closeness_c = nx.closeness_centrality(g)
    clustering_c = nx.clustering(g.to_undirected())

    out = {}
    for metric_name, values_dict in [
        ("degree_centrality", degree_c),
        ("closeness_centrality", closeness_c),
        ("clustering_coefficient", clustering_c),
    ]:
        stats = _stats(list(values_dict.values()))
        for stat_name, val in stats.items():
            out[f"{metric_name}_{stat_name}"] = val

    return out


def detect_flattening_outlier(g: nx.DiGraph, zscore_threshold: float = 3.0) -> tuple[bool, list[str]]:
    """
    Control-flow flattening signature: a single dispatcher node with
    abnormally high degree relative to the rest of the graph, while the
    rest of the distribution stays flat. Returns (suspected, outlier_node_ids).
    """
    if g.number_of_nodes() < 5:
        return False, []

    degrees = dict(g.degree())
    values = list(degrees.values())
    mean = statistics.mean(values)
    std = statistics.pstdev(values)

    if std == 0:
        return False, []

    outliers = [
        node for node, deg in degrees.items()
        if (deg - mean) / std >= zscore_threshold
    ]

    return (len(outliers) > 0), outliers
