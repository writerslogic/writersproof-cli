// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! KD-tree for nearest-neighbor search in low-dimensional embedding spaces.
//!
//! Optimized for the Lyapunov analysis use case: 5D phase-space points,
//! 1000-5000 points, with a temporal exclusion constraint on neighbors.

use super::stats::sq_dist;

/// A static KD-tree built over a flat embedding buffer.
pub struct KdTree<'a> {
    /// Flat embedding data: `points[i*dim..(i+1)*dim]` is point i.
    points: &'a [f64],
    dim: usize,
    /// Permutation of point indices, implicitly encoding the tree structure.
    /// `nodes[0..n]` are the tree nodes in BFS-like layout.
    nodes: Vec<KdNode>,
}

struct KdNode {
    point_idx: usize,
    split_dim: usize,
    left: Option<usize>,
    right: Option<usize>,
}

impl<'a> KdTree<'a> {
    /// Build a KD-tree from a flat embedding buffer.
    ///
    /// `points` has layout `[p0_d0, p0_d1, ..., p0_dN, p1_d0, ...]`.
    /// `count` is the number of points, `dim` is the dimensionality.
    pub fn build(points: &'a [f64], count: usize, dim: usize) -> Self {
        let mut indices: Vec<usize> = (0..count).collect();
        let mut nodes = Vec::with_capacity(count);
        Self::build_recursive(points, dim, &mut indices, 0, &mut nodes);
        KdTree { points, dim, nodes }
    }

    fn build_recursive(
        points: &[f64],
        dim: usize,
        indices: &mut [usize],
        depth: usize,
        nodes: &mut Vec<KdNode>,
    ) -> Option<usize> {
        if indices.is_empty() {
            return None;
        }

        let split_dim = depth % dim;

        // Partition around median
        indices.sort_unstable_by(|&a, &b| {
            let va = points[a * dim + split_dim];
            let vb = points[b * dim + split_dim];
            va.partial_cmp(&vb).unwrap_or(std::cmp::Ordering::Equal)
        });

        let mid = indices.len() / 2;
        let point_idx = indices[mid];
        let node_idx = nodes.len();

        // Push placeholder
        nodes.push(KdNode {
            point_idx,
            split_dim,
            left: None,
            right: None,
        });

        let (left_slice, right_slice) = indices.split_at_mut(mid);
        // right_slice[0] is the median point — skip it
        let right_slice = if right_slice.len() > 1 {
            &mut right_slice[1..]
        } else {
            &mut []
        };

        let left = Self::build_recursive(points, dim, left_slice, depth + 1, nodes);
        let right = Self::build_recursive(points, dim, right_slice, depth + 1, nodes);

        nodes[node_idx].left = left;
        nodes[node_idx].right = right;

        Some(node_idx)
    }

    #[inline]
    fn get_point(&self, idx: usize) -> &[f64] {
        &self.points[idx * self.dim..(idx + 1) * self.dim]
    }

    /// Find the nearest neighbor to `query_idx`, excluding points where
    /// `|query_idx - neighbor_idx| < min_temporal_sep`.
    ///
    /// Returns `(neighbor_index, squared_distance)` or `None` if no valid
    /// neighbor exists.
    pub fn nearest_neighbor(
        &self,
        query_idx: usize,
        min_temporal_sep: usize,
    ) -> Option<(usize, f64)> {
        if self.nodes.is_empty() {
            return None;
        }
        let query = self.get_point(query_idx);
        let mut best_idx = usize::MAX;
        let mut best_dist_sq = f64::INFINITY;
        self.nn_search(
            0,
            query,
            query_idx,
            min_temporal_sep,
            &mut best_idx,
            &mut best_dist_sq,
        );
        if best_dist_sq.is_finite() {
            Some((best_idx, best_dist_sq))
        } else {
            None
        }
    }

    fn nn_search(
        &self,
        node_idx: usize,
        query: &[f64],
        query_point_idx: usize,
        min_sep: usize,
        best_idx: &mut usize,
        best_dist_sq: &mut f64,
    ) {
        let node = &self.nodes[node_idx];
        let point = self.get_point(node.point_idx);

        // Check this node (with temporal exclusion)
        let temporal_ok = query_point_idx.abs_diff(node.point_idx) >= min_sep;
        if temporal_ok {
            let dist = sq_dist(query, point);
            if dist < *best_dist_sq && dist > 0.0 {
                *best_dist_sq = dist;
                *best_idx = node.point_idx;
            }
        }

        let split_val = point[node.split_dim];
        let query_val = query[node.split_dim];
        let diff = query_val - split_val;
        let diff_sq = diff * diff;

        // Visit the closer subtree first
        let (first, second) = if diff < 0.0 {
            (node.left, node.right)
        } else {
            (node.right, node.left)
        };

        if let Some(child) = first {
            self.nn_search(
                child,
                query,
                query_point_idx,
                min_sep,
                best_idx,
                best_dist_sq,
            );
        }

        // Only visit the farther subtree if the splitting plane is closer than current best
        if diff_sq < *best_dist_sq {
            if let Some(child) = second {
                self.nn_search(
                    child,
                    query,
                    query_point_idx,
                    min_sep,
                    best_idx,
                    best_dist_sq,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nearest_neighbor_2d() {
        // 4 points in 2D: (0,0), (1,0), (0,1), (3,3)
        let points = [0.0, 0.0, 1.0, 0.0, 0.0, 1.0, 3.0, 3.0];
        let tree = KdTree::build(&points, 4, 2);
        // Nearest to point 0 (0,0) with no temporal exclusion
        let (idx, dist) = tree.nearest_neighbor(0, 0).unwrap();
        assert!(idx == 1 || idx == 2); // both at distance 1.0
        assert!((dist - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_temporal_exclusion() {
        // 4 points in 2D: (0,0), (0.1,0), (0,0.1), (3,3)
        let points = [0.0, 0.0, 0.1, 0.0, 0.0, 0.1, 3.0, 3.0];
        let tree = KdTree::build(&points, 4, 2);
        // Nearest to point 0 excluding within temporal sep 3
        // Points 0, 1, 2 are excluded, so nearest is point 3
        let (idx, _) = tree.nearest_neighbor(0, 3).unwrap();
        assert_eq!(idx, 3);
    }

    #[test]
    fn test_no_valid_neighbor() {
        let points = [0.0, 0.0, 1.0, 1.0];
        let tree = KdTree::build(&points, 2, 2);
        // Exclude all neighbors (temporal sep = 10 with only 2 points)
        assert!(tree.nearest_neighbor(0, 10).is_none());
    }

    #[test]
    fn test_identical_points() {
        // All same point — dist is 0.0, should not match (dist > 0.0 guard)
        let points = [1.0, 1.0, 1.0, 1.0, 1.0, 1.0];
        let tree = KdTree::build(&points, 3, 2);
        assert!(tree.nearest_neighbor(0, 0).is_none());
    }
}
