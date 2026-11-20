//! `FileStore`: the in-memory files behind `PUT /mockserver/files/{store,retrieve,list,delete}` (`HttpState`), one
//! store per server, emptied by `reset`.
//!
//! Upstream keeps the files in a `ConcurrentHashMap<String, byte[]>`, and `list` prints its key set, so the order is
//! that map's: [`FileStore`] models its bins (a table of 16 created on first use, doubled once the count reaches three
//! quarters of it, `transfer`'s split of each bin, `treeifyBin`'s presize below 64 slots, tree bins taking new nodes
//! at their head, and `clear` keeping the table). A tree bin keeps `TreeBin`'s red-black tree ([`Tree`]), since a
//! removal turns the bin back into a list by the tree's shape.

use std::collections::HashMap;

use jackson::JsonNode;
use parking_lot::Mutex;

use crate::reply::Reply;
use crate::request::HttpRequest;
use crate::state::State;

/// `TREEIFY_THRESHOLD`, `UNTREEIFY_THRESHOLD` and `MIN_TREEIFY_CAPACITY`.
const TREEIFY: usize = 8;
const UNTREEIFY: usize = 6;
const MIN_TREEIFY_CAPACITY: usize = 64;

#[derive(Default)]
pub struct FileStore {
    inner: Mutex<Bins>,
}

/// One slot of the table: its keys in `ConcurrentHashMap`'s iteration order, and the tree of a `TreeBin`.
#[derive(Clone, Default)]
struct Bin {
    names: Vec<String>,
    tree: Option<Tree>,
}

#[derive(Clone)]
struct TreeNode {
    name: String,
    hash: u32,
    left: Option<usize>,
    right: Option<usize>,
    parent: Option<usize>,
    red: bool,
    removed: bool,
}

/// `TreeBin`'s red-black tree, ordered by hash, then `String.compareTo`; its nodes stay in `nodes` once removed.
#[derive(Clone, Default)]
struct Tree {
    nodes: Vec<TreeNode>,
    root: Option<usize>,
}

impl Tree {
    /// `new TreeBin(first)`: the nodes inserted in list order.
    fn build(names: &[String]) -> Tree {
        let mut tree = Tree::default();
        names.iter().for_each(|name| tree.insert(name));
        tree
    }

    fn red(&self, x: Option<usize>) -> bool {
        x.is_some_and(|x| self.nodes[x].red)
    }

    fn left(&self, x: usize) -> Option<usize> {
        self.nodes[x].left
    }

    fn right(&self, x: usize) -> Option<usize> {
        self.nodes[x].right
    }

    fn parent(&self, x: usize) -> Option<usize> {
        self.nodes[x].parent
    }

    /// The `TreeBin` constructor's and `putTreeVal`'s insertion of a new key.
    fn insert(&mut self, name: &str) {
        let hash = spread(name);
        let x = self.nodes.len();
        self.nodes.push(TreeNode { name: name.to_string(), hash, left: None, right: None, parent: None, red: false, removed: false });
        let Some(mut p) = self.root else {
            self.root = Some(x);
            return;
        };
        loop {
            let ph = self.nodes[p].hash;
            let left = if ph != hash { ph > hash } else { name.encode_utf16().cmp(self.nodes[p].name.encode_utf16()).is_le() };
            let next = if left { self.left(p) } else { self.right(p) };
            match next {
                Some(next) => p = next,
                None => {
                    self.nodes[x].parent = Some(p);
                    if left { self.nodes[p].left = Some(x) } else { self.nodes[p].right = Some(x) }
                    self.balance_insertion(x);
                    return;
                }
            }
        }
    }

    fn replace_child(&mut self, parent: Option<usize>, old: usize, new: usize) {
        match parent {
            None => self.root = Some(new),
            Some(pp) if self.left(pp) == Some(old) => self.nodes[pp].left = Some(new),
            Some(pp) => self.nodes[pp].right = Some(new),
        }
    }

    fn rotate_left(&mut self, p: usize) {
        let Some(r) = self.right(p) else { return };
        let rl = self.left(r);
        self.nodes[p].right = rl;
        if let Some(rl) = rl {
            self.nodes[rl].parent = Some(p);
        }
        let pp = self.parent(p);
        self.nodes[r].parent = pp;
        if pp.is_none() {
            self.nodes[r].red = false;
        }
        self.replace_child(pp, p, r);
        self.nodes[r].left = Some(p);
        self.nodes[p].parent = Some(r);
    }

    fn rotate_right(&mut self, p: usize) {
        let Some(l) = self.left(p) else { return };
        let lr = self.right(l);
        self.nodes[p].left = lr;
        if let Some(lr) = lr {
            self.nodes[lr].parent = Some(p);
        }
        let pp = self.parent(p);
        self.nodes[l].parent = pp;
        if pp.is_none() {
            self.nodes[l].red = false;
        }
        match pp {
            None => self.root = Some(l),
            Some(pp) if self.right(pp) == Some(p) => self.nodes[pp].right = Some(l),
            Some(pp) => self.nodes[pp].left = Some(l),
        }
        self.nodes[l].right = Some(p);
        self.nodes[p].parent = Some(l);
    }

    fn balance_insertion(&mut self, mut x: usize) {
        self.nodes[x].red = true;
        loop {
            let Some(xp) = self.parent(x) else {
                self.nodes[x].red = false;
                self.root = Some(x);
                return;
            };
            if !self.nodes[xp].red {
                return;
            }
            let Some(xpp) = self.parent(xp) else { return };
            let xp_is_left = self.left(xpp) == Some(xp);
            let uncle = if xp_is_left { self.right(xpp) } else { self.left(xpp) };
            if self.red(uncle) {
                self.nodes[uncle.unwrap()].red = false;
                self.nodes[xp].red = false;
                self.nodes[xpp].red = true;
                x = xpp;
                continue;
            }
            let (mut xp, mut xpp) = (Some(xp), Some(xpp));
            let inner = if xp_is_left { self.right(xp.unwrap()) } else { self.left(xp.unwrap()) };
            if inner == Some(x) {
                x = xp.unwrap();
                if xp_is_left { self.rotate_left(x) } else { self.rotate_right(x) }
                xp = self.parent(x);
                xpp = xp.and_then(|xp| self.parent(xp));
            }
            if let Some(xp) = xp {
                self.nodes[xp].red = false;
                if let Some(xpp) = xpp {
                    self.nodes[xpp].red = true;
                    if xp_is_left { self.rotate_right(xpp) } else { self.rotate_left(xpp) }
                }
            }
        }
    }

    /// `removeTreeNode` after the node is unlinked from the list: `true` when the tree is too small to keep (the bin
    /// turns back into a list), decided by its shape before the node leaves it.
    fn remove(&mut self, name: &str) -> bool {
        let Some(r) = self.root else { return true };
        if self.right(r).is_none() || self.left(r).is_none_or(|rl| self.left(rl).is_none()) {
            return true;
        }
        let Some(p) = self.nodes.iter().position(|n| !n.removed && n.name == name) else { return false };
        let (pl, pr) = (self.left(p), self.right(p));
        let replacement = match (pl, pr) {
            (Some(pl), Some(pr)) => {
                let mut s = pr;
                while let Some(sl) = self.left(s) {
                    s = sl;
                }
                let c = self.nodes[s].red;
                self.nodes[s].red = self.nodes[p].red;
                self.nodes[p].red = c;
                let sr = self.right(s);
                let pp = self.parent(p);
                if s == pr {
                    self.nodes[p].parent = Some(s);
                    self.nodes[s].right = Some(p);
                } else {
                    let sp = self.parent(s);
                    self.nodes[p].parent = sp;
                    if let Some(sp) = sp {
                        if self.left(sp) == Some(s) { self.nodes[sp].left = Some(p) } else { self.nodes[sp].right = Some(p) }
                    }
                    self.nodes[s].right = Some(pr);
                    self.nodes[pr].parent = Some(s);
                }
                self.nodes[p].left = None;
                self.nodes[p].right = sr;
                if let Some(sr) = sr {
                    self.nodes[sr].parent = Some(p);
                }
                self.nodes[s].left = Some(pl);
                self.nodes[pl].parent = Some(s);
                self.nodes[s].parent = pp;
                self.replace_child(pp, p, s);
                sr.unwrap_or(p)
            }
            (Some(child), None) | (None, Some(child)) => child,
            (None, None) => p,
        };
        if replacement != p {
            let pp = self.parent(p);
            self.nodes[replacement].parent = pp;
            self.replace_child(pp, p, replacement);
            self.nodes[p].left = None;
            self.nodes[p].right = None;
            self.nodes[p].parent = None;
        }
        if !self.nodes[p].red {
            self.balance_deletion(Some(replacement));
        }
        if p == replacement && let Some(pp) = self.parent(p) {
            if self.left(pp) == Some(p) {
                self.nodes[pp].left = None;
            } else if self.right(pp) == Some(p) {
                self.nodes[pp].right = None;
            }
            self.nodes[p].parent = None;
        }
        self.nodes[p].removed = true;
        false
    }

    fn balance_deletion(&mut self, mut x: Option<usize>) {
        loop {
            let Some(xi) = x else { return };
            if self.root == Some(xi) {
                return;
            }
            let Some(mut xp) = self.parent(xi) else {
                self.nodes[xi].red = false;
                self.root = Some(xi);
                return;
            };
            if self.nodes[xi].red {
                self.nodes[xi].red = false;
                return;
            }
            let x_is_left = self.left(xp) == Some(xi);
            let sibling = |t: &Tree, xp: usize| if x_is_left { t.right(xp) } else { t.left(xp) };
            let mut w = sibling(self, xp);
            if self.red(w) {
                self.nodes[w.unwrap()].red = false;
                self.nodes[xp].red = true;
                if x_is_left { self.rotate_left(xp) } else { self.rotate_right(xp) }
                match self.parent(xi) {
                    Some(p) => {
                        xp = p;
                        w = sibling(self, xp);
                    }
                    None => {
                        x = None;
                        continue;
                    }
                }
            }
            let Some(ws) = w else {
                x = Some(xp);
                continue;
            };
            let (near, far) = if x_is_left { (self.left(ws), self.right(ws)) } else { (self.right(ws), self.left(ws)) };
            if !self.red(far) && !self.red(near) {
                self.nodes[ws].red = true;
                x = Some(xp);
                continue;
            }
            let mut xp = Some(xp);
            let mut w = Some(ws);
            if !self.red(far) {
                if let Some(near) = near {
                    self.nodes[near].red = false;
                }
                self.nodes[ws].red = true;
                if x_is_left { self.rotate_right(ws) } else { self.rotate_left(ws) }
                xp = self.parent(xi);
                w = xp.and_then(|xp| sibling(self, xp));
            }
            if let Some(w) = w {
                self.nodes[w].red = xp.is_some_and(|xp| self.nodes[xp].red);
                let far = if x_is_left { self.right(w) } else { self.left(w) };
                if let Some(far) = far {
                    self.nodes[far].red = false;
                }
            }
            if let Some(xp) = xp {
                self.nodes[xp].red = false;
                if x_is_left { self.rotate_left(xp) } else { self.rotate_right(xp) }
            }
            x = self.root;
        }
    }
}

#[derive(Default)]
struct Bins {
    /// The table; empty until the first `put`.
    table: Vec<Bin>,
    files: HashMap<String, Vec<u8>>,
}

/// `ConcurrentHashMap.spread(String.hashCode())`.
fn spread(name: &str) -> u32 {
    let mut h: i32 = 0;
    for unit in name.encode_utf16() {
        h = h.wrapping_mul(31).wrapping_add(i32::from(unit));
    }
    let h = h as u32;
    (h ^ (h >> 16)) & 0x7FFF_FFFF
}

impl Bins {
    fn index(&self, name: &str) -> usize {
        spread(name) as usize & (self.table.len() - 1)
    }

    /// `putVal`.
    fn put(&mut self, name: &str, content: Vec<u8>) {
        if self.table.is_empty() {
            self.table = vec![Bin::default(); 16];
        }
        let added = self.files.insert(name.to_string(), content).is_none();
        let i = self.index(name);
        let bin = &mut self.table[i];
        if let Some(tree) = &mut bin.tree {
            // `putTreeVal` links a new node in front of `first`
            if added {
                bin.names.insert(0, name.to_string());
                tree.insert(name);
            }
        } else {
            // `binCount`: the nodes walked, up to the match or the last node
            let walked = if added { bin.names.len() } else { bin.names.iter().position(|k| k == name).map_or(0, |p| p + 1) };
            if added {
                bin.names.push(name.to_string());
            }
            if walked >= TREEIFY {
                self.treeify_bin(i);
            }
        }
        if added {
            // `addCount`: resize while the count reaches `sizeCtl` (three quarters of the table)
            while self.files.len() >= self.size_ctl() {
                self.transfer();
            }
        }
    }

    fn size_ctl(&self) -> usize {
        let n = self.table.len();
        n - (n >> 2)
    }

    /// `treeifyBin`: below 64 slots the table grows instead (`tryPresize(n << 1)`).
    fn treeify_bin(&mut self, i: usize) {
        let n = self.table.len();
        if n < MIN_TREEIFY_CAPACITY {
            let size = n << 1;
            let c = (size + (size >> 1) + 1).next_power_of_two();
            while c > self.size_ctl() {
                self.transfer();
            }
        } else {
            let bin = &mut self.table[i];
            bin.tree = Some(Tree::build(&bin.names));
        }
    }

    /// `ConcurrentHashMap.transfer`: each bin splits into a low and a high bin. In a list bin the run of nodes at its
    /// end that all go one way keeps its order and the nodes before it are prepended one by one (so they come out
    /// reversed); a tree bin's halves keep their order, each a tree only above six nodes: the same tree when the other
    /// half is empty, else one built anew from the half.
    fn transfer(&mut self) {
        let n = self.table.len();
        let mut next = vec![Bin::default(); n * 2];
        let high = |name: &String| spread(name) as usize & n != 0;
        for (i, bin) in std::mem::take(&mut self.table).into_iter().enumerate() {
            let names = bin.names;
            if names.is_empty() {
                continue;
            }
            let (low, hi): (Vec<String>, Vec<String>) = if bin.tree.is_some() {
                names.into_iter().partition(|k| !high(k))
            } else {
                let last_run = (1..names.len()).rev().find(|&j| high(&names[j]) != high(&names[j - 1])).unwrap_or(0);
                let (mut low, mut hi) = (Vec::new(), Vec::new());
                for name in names[..last_run].iter().rev() {
                    if high(name) { hi.push(name.clone()) } else { low.push(name.clone()) }
                }
                let run = names[last_run..].to_vec();
                if high(&names[last_run]) { hi.extend(run) } else { low.extend(run) }
                (low, hi)
            };
            let half = |names: &[String], other: &[String]| match &bin.tree {
                Some(_) if names.len() <= UNTREEIFY => None,
                Some(tree) if other.is_empty() => Some(tree.clone()),
                Some(_) => Some(Tree::build(names)),
                None => None,
            };
            next[i] = Bin { tree: half(&low, &hi), names: low.clone() };
            next[i + n] = Bin { tree: half(&hi, &low), names: hi };
        }
        self.table = next;
    }

    fn remove(&mut self, name: &str) -> bool {
        if self.files.remove(name).is_none() {
            return false;
        }
        let i = self.index(name);
        let bin = &mut self.table[i];
        bin.names.retain(|k| k != name);
        // `replaceNode`: `untreeify` when the list is empty or `removeTreeNode` finds the tree too small
        if bin.names.is_empty() || bin.tree.as_mut().is_some_and(|tree| tree.remove(name)) {
            bin.tree = None;
        }
        true
    }
}

impl FileStore {
    pub fn store(&self, name: &str, content: Vec<u8>) {
        self.inner.lock().put(name, content);
    }

    pub fn retrieve(&self, name: &str) -> Option<Vec<u8>> {
        self.inner.lock().files.get(name).cloned()
    }

    pub fn delete(&self, name: &str) -> bool {
        self.inner.lock().remove(name)
    }

    /// `listFiles()`: the key set in `ConcurrentHashMap` iteration order.
    pub fn names(&self) -> Vec<String> {
        self.inner.lock().table.iter().flat_map(|bin| bin.names.iter().cloned()).collect()
    }

    /// `ConcurrentHashMap.clear`: the entries go, the table keeps its size.
    pub fn reset(&self) {
        let mut bins = self.inner.lock();
        bins.files.clear();
        bins.table.iter_mut().for_each(|bin| *bin = Bin::default());
    }
}

fn text(status: u32, message: impl Into<String>) -> Reply {
    Reply::api_header(status, "text/plain", message.into())
}

/// `ObjectMapper.readTree(getBodyAsJsonOrXmlString())`: a missing body is a `null` argument, a blank one a missing
/// node; the error is the exception message.
fn read_body(request: &HttpRequest) -> Result<JsonNode, String> {
    if request.body.is_empty() {
        return Err("argument \"content\" is null".into());
    }
    let body = request.body_json_or_xml_str();
    if body.trim().is_empty() {
        return Ok(JsonNode::Missing);
    }
    crate::jnode::read_tree(&body).map_err(|e| e.message)
}

/// `Base64.getDecoder().decode(String)`: the text is read as ISO-8859-1 bytes, `?` for any other UTF-16 unit.
fn decode_base64(content: &str) -> Result<Vec<u8>, String> {
    let latin1: Vec<u8> = content.encode_utf16().map(|u| if u <= 0xFF { u as u8 } else { b'?' }).collect();
    crate::tls::x509::java_base64_decode(&latin1)
}

/// The four `files/*` operations of `HttpState.handle` (`op` without the `/mockserver` prefix); `None` for any
/// other request. Authentication is the caller's.
pub fn route(state: &State, request: &HttpRequest, op: &str) -> Option<Reply> {
    if request.method != "PUT" {
        return None;
    }
    let files = &state.files;
    Some(match op {
        "/files/store" => {
            if request.body.is_empty() || request.body_json_or_xml_str().trim().is_empty() {
                return Some(text(400, "request body is empty"));
            }
            let stored = read_body(request).and_then(|node| match (node.get("name"), node.get("content")) {
                (Some(name), Some(content)) => {
                    let (name, content) = (name.as_text(), content.as_text());
                    let bytes = if node.get("base64").is_some_and(JsonNode::as_boolean) { decode_base64(&content)? } else { content.into_bytes() };
                    let size = bytes.len();
                    files.store(&name, bytes);
                    Ok(Some((name, size)))
                }
                _ => Ok(None),
            });
            match stored {
                // the name goes into the answer as it is, unescaped
                Ok(Some((name, size))) => Reply::api_body(201, "application/json", format!("{{\"name\":\"{name}\",\"size\":{size}}}")),
                Ok(None) => text(400, "request body must contain 'name' and 'content' fields"),
                Err(message) => text(400, format!("failed to store file: {message}")),
            }
        }
        "/files/retrieve" | "/files/delete" => {
            let verb = if op == "/files/retrieve" { "retrieve" } else { "delete" };
            let name = match read_body(request) {
                Ok(node) => node.get("name").map(JsonNode::as_text).filter(|n| !n.trim().is_empty()),
                Err(message) => return Some(text(400, format!("failed to {verb} file: {message}"))),
            };
            let Some(name) = name else {
                return Some(text(400, "request body must contain 'name' field"));
            };
            match verb {
                "retrieve" => match files.retrieve(&name) {
                    Some(content) => {
                        let mut reply = Reply::api(200);
                        reply.body = content.into();
                        reply
                    }
                    None => text(404, format!("file not found: {name}")),
                },
                _ if files.delete(&name) => Reply::api(200),
                _ => text(404, format!("file not found: {name}")),
            }
        }
        "/files/list" => Reply::api_body(200, "application/json", crate::json::pretty(&serde_json::json!(files.names()))),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(names: &[&str]) -> FileStore {
        let files = FileStore::default();
        for name in names {
            files.store(name, name.as_bytes().to_vec());
        }
        files
    }

    #[test]
    fn a_bin_keeps_insertion_order_until_the_table_doubles() {
        // all six in bin 1 of 16
        let files = store(&["a", "q", "A", "Q", "1", "!", "b"]);
        assert_eq!(files.names(), ["a", "q", "A", "Q", "1", "!", "b"]);
    }

    #[test]
    fn transfer_reverses_the_nodes_before_the_last_run() {
        // the twelfth entry doubles the table: bin 1 splits into 1 (`a`, `A`, `!`) and 17 (`q`, `Q`, `1`); `!` is
        // the last run, the rest are prepended
        let files = store(&["a", "q", "A", "Q", "1", "!", "b", "c", "d", "e", "f", "g"]);
        assert_eq!(files.names(), ["A", "a", "!", "b", "c", "d", "e", "f", "g", "1", "Q", "q"]);
    }

    #[test]
    fn reset_keeps_the_doubled_table() {
        let files = store(&["a", "q", "A", "Q", "1", "!", "b", "c", "d", "e", "f", "g"]);
        files.reset();
        files.store("q", vec![]);
        files.store("a", vec![]);
        assert_eq!(files.names(), ["a", "q"]);
        assert!(files.retrieve("A").is_none());
    }

    #[test]
    fn a_crowded_bin_presizes_the_table_then_turns_into_a_tree() {
        // all collide up to 256 slots
        let files = store(&["aB", "hi", "iJ", "pq", "qR", "r3", "xy", "yZ", "Gh", "HI", "Op", "PQ"]);
        assert_eq!(files.names(), ["PQ", "Op", "aB", "hi", "iJ", "pq", "qR", "r3", "xy", "yZ", "Gh", "HI"]);
        files.store("q", vec![]);
        assert_eq!(files.names().last().unwrap(), "q");
    }

    #[test]
    fn a_removed_name_comes_back_at_its_bins_end() {
        let files = store(&["a", "q", "A"]);
        assert!(files.delete("a"));
        assert!(!files.delete("a"));
        files.store("a", vec![]);
        files.store("q", b"new".to_vec());
        assert_eq!(files.names(), ["q", "A", "a"]);
        assert_eq!(files.retrieve("q").unwrap(), b"new");
    }
}
