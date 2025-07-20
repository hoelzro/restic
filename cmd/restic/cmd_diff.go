package main

import (
	"context"
	"encoding/json"
	"maps"
	"path"
	"reflect"
	"slices"
	"sort"
	"strings"

	"github.com/restic/restic/internal/debug"
	"github.com/restic/restic/internal/errors"
	"github.com/restic/restic/internal/restic"
	"github.com/restic/restic/internal/ui"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func newDiffCommand() *cobra.Command {
	var opts DiffOptions

	cmd := &cobra.Command{
		Use:   "diff [flags] snapshotID snapshotID",
		Short: "Show differences between two snapshots",
		Long: `
The "diff" command shows differences from the first to the second snapshot. The
first characters in each line display what has happened to a particular file or
directory:

* +  The item was added
* -  The item was removed
* U  The metadata (access mode, timestamps, ...) for the item was updated
* M  The file's content was modified
* T  The type was changed, e.g. a file was made a symlink
* ?  Bitrot detected: The file's content has changed but all metadata is the same

Metadata comparison will likely not work if a backup was created using the
'--ignore-inode' or '--ignore-ctime' option.

To only compare files in specific subfolders, you can use the
"snapshotID:subfolder" syntax, where "subfolder" is a path within the
snapshot.

EXIT STATUS
===========

Exit status is 0 if the command was successful.
Exit status is 1 if there was any error.
Exit status is 10 if the repository does not exist.
Exit status is 11 if the repository is already locked.
Exit status is 12 if the password is incorrect.
`,
		GroupID:           cmdGroupDefault,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDiff(cmd.Context(), opts, globalOptions, args)
		},
	}

	opts.AddFlags(cmd.Flags())
	return cmd
}

// DiffOptions collects all options for the diff command.
type DiffOptions struct {
	ShowMetadata bool
	Tree         bool
}

func (opts *DiffOptions) AddFlags(f *pflag.FlagSet) {
	f.BoolVar(&opts.ShowMetadata, "metadata", false, "print changes in metadata")
	f.BoolVar(&opts.Tree, "tree", false, "print per-path blob statistics in JSON")
}

func loadSnapshot(ctx context.Context, be restic.Lister, repo restic.LoaderUnpacked, desc string) (*restic.Snapshot, string, error) {
	sn, subfolder, err := restic.FindSnapshot(ctx, be, repo, desc)
	if err != nil {
		return nil, "", errors.Fatal(err.Error())
	}
	return sn, subfolder, err
}

// Comparer collects all things needed to compare two snapshots.
type Comparer struct {
	repo        restic.BlobLoader
	opts        DiffOptions
	printChange func(change *Change)
}

type Change struct {
	MessageType string `json:"message_type"` // "change"
	Path        string `json:"path"`
	Modifier    string `json:"modifier"`
}

func NewChange(path string, mode string) *Change {
	return &Change{MessageType: "change", Path: path, Modifier: mode}
}

// DiffStat collects stats for all types of items.
type DiffStat struct {
	Files     int    `json:"files"`
	Dirs      int    `json:"dirs"`
	Others    int    `json:"others"`
	DataBlobs int    `json:"data_blobs"`
	TreeBlobs int    `json:"tree_blobs"`
	Bytes     uint64 `json:"bytes"`
}

// Add adds stats information for node to s.
func (s *DiffStat) Add(node *restic.Node) {
	if node == nil {
		return
	}

	switch node.Type {
	case restic.NodeTypeFile:
		s.Files++
	case restic.NodeTypeDir:
		s.Dirs++
	default:
		s.Others++
	}
}

// addBlobs adds the blobs of node to s.
func addBlobs(bs restic.BlobSet, node *restic.Node) {
	if node == nil {
		return
	}

	switch node.Type {
	case restic.NodeTypeFile:
		for _, blob := range node.Content {
			h := restic.BlobHandle{
				ID:   blob,
				Type: restic.DataBlob,
			}
			bs.Insert(h)
		}
	case restic.NodeTypeDir:
		h := restic.BlobHandle{
			ID:   *node.Subtree,
			Type: restic.TreeBlob,
		}
		bs.Insert(h)
	}
}

type DiffStatsContainer struct {
	MessageType                          string         `json:"message_type"` // "statistics"
	SourceSnapshot                       string         `json:"source_snapshot"`
	TargetSnapshot                       string         `json:"target_snapshot"`
	ChangedFiles                         int            `json:"changed_files"`
	Added                                DiffStat       `json:"added"`
	Removed                              DiffStat       `json:"removed"`
	BlobsBefore, BlobsAfter, BlobsCommon restic.BlobSet `json:"-"`
}

type TreeDiffStats struct {
	Path         string                    `json:"path"`
	BlobsAdded   int                       `json:"blobs_added"`
	BytesAdded   uint64                    `json:"bytes_added"`
	BlobsRemoved int                       `json:"blobs_removed"`
	BytesRemoved uint64                    `json:"bytes_removed"`
	BlobsCommon  int                       `json:"blobs_common"`
	BytesCommon  uint64                    `json:"bytes_common"`
	Children     map[string]*TreeDiffStats `json:"children,omitempty"`
}

// updateBlobs updates the blob counters in the stats struct.
func updateBlobs(repo restic.Loader, blobs restic.BlobSet, stats *DiffStat) {
	for h := range blobs {
		switch h.Type {
		case restic.DataBlob:
			stats.DataBlobs++
		case restic.TreeBlob:
			stats.TreeBlobs++
		}

		size, found := repo.LookupBlobSize(h.Type, h.ID)
		if !found {
			Warnf("unable to find blob size for %v\n", h)
			continue
		}

		stats.Bytes += uint64(size)
	}
}

func (c *Comparer) printDir(ctx context.Context, mode string, stats *DiffStat, blobs restic.BlobSet, prefix string, id restic.ID) error {
	debug.Log("print %v tree %v", mode, id)
	tree, err := restic.LoadTree(ctx, c.repo, id)
	if err != nil {
		return err
	}

	for _, node := range tree.Nodes {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		name := path.Join(prefix, node.Name)
		if node.Type == restic.NodeTypeDir {
			name += "/"
		}
		c.printChange(NewChange(name, mode))
		stats.Add(node)
		addBlobs(blobs, node)

		if node.Type == restic.NodeTypeDir {
			err := c.printDir(ctx, mode, stats, blobs, name, *node.Subtree)
			if err != nil && err != context.Canceled {
				Warnf("error: %v\n", err)
			}
		}
	}

	return ctx.Err()
}

func (c *Comparer) collectDir(ctx context.Context, blobs restic.BlobSet, id restic.ID) error {
	debug.Log("print tree %v", id)
	tree, err := restic.LoadTree(ctx, c.repo, id)
	if err != nil {
		return err
	}

	for _, node := range tree.Nodes {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		addBlobs(blobs, node)

		if node.Type == restic.NodeTypeDir {
			err := c.collectDir(ctx, blobs, *node.Subtree)
			if err != nil && err != context.Canceled {
				Warnf("error: %v\n", err)
			}
		}
	}

	return ctx.Err()
}

func uniqueNodeNames(tree1, tree2 *restic.Tree) (tree1Nodes, tree2Nodes map[string]*restic.Node, uniqueNames []string) {
	names := make(map[string]struct{})
	tree1Nodes = make(map[string]*restic.Node)
	for _, node := range tree1.Nodes {
		tree1Nodes[node.Name] = node
		names[node.Name] = struct{}{}
	}

	tree2Nodes = make(map[string]*restic.Node)
	for _, node := range tree2.Nodes {
		tree2Nodes[node.Name] = node
		names[node.Name] = struct{}{}
	}

	uniqueNames = make([]string, 0, len(names))
	for name := range names {
		uniqueNames = append(uniqueNames, name)
	}

	sort.Strings(uniqueNames)
	return tree1Nodes, tree2Nodes, uniqueNames
}

func collectPathBlobs(ctx context.Context, repo restic.BlobLoader, prefix string, id restic.ID, paths map[string]restic.BlobSet) (restic.BlobSet, error) {
	tree, err := restic.LoadTree(ctx, repo, id)
	if err != nil {
		return nil, err
	}
	bs := restic.NewBlobSet()
	bs.Insert(restic.BlobHandle{ID: id, Type: restic.TreeBlob})
	for _, node := range tree.Nodes {
		nodePath := path.Join(prefix, node.Name)
		if node.Type == restic.NodeTypeDir {
			nodePath += "/"
		}
		nbs := restic.NewBlobSet()
		addBlobs(nbs, node)
		if node.Type == restic.NodeTypeDir {
			sub, err := collectPathBlobs(ctx, repo, nodePath, *node.Subtree, paths)
			if err != nil {
				return nil, err
			}
			nbs.Merge(sub)
		}
		paths[nodePath] = nbs
		bs.Merge(nbs)
	}
	paths[prefix] = bs
	return bs, nil
}

func computeTreeStat(repo restic.Repository, set1, set2 restic.BlobSet) TreeDiffStats {
	added := set2.Sub(set1)
	removed := set1.Sub(set2)
	common := set1.Intersect(set2)

	addCount, addBytes := blobCountSize(repo, added)
	remCount, remBytes := blobCountSize(repo, removed)
	comCount, comBytes := blobCountSize(repo, common)

	return TreeDiffStats{
		BlobsAdded:   addCount,
		BytesAdded:   addBytes,
		BlobsRemoved: remCount,
		BytesRemoved: remBytes,
		BlobsCommon:  comCount,
		BytesCommon:  comBytes,
	}
}

func insertTreeStat(root *TreeDiffStats, stat *TreeDiffStats) {
	if stat.Path == "/" {
		root.BlobsAdded = stat.BlobsAdded
		root.BytesAdded = stat.BytesAdded
		root.BlobsRemoved = stat.BlobsRemoved
		root.BytesRemoved = stat.BytesRemoved
		root.BlobsCommon = stat.BlobsCommon
		root.BytesCommon = stat.BytesCommon
		return
	}

	trimmed := strings.Trim(stat.Path, "/")
	dir := strings.HasSuffix(stat.Path, "/")
	parts := strings.Split(trimmed, "/")

	node := root
	for i, part := range parts {
		isLast := i == len(parts)-1
		key := part
		if !isLast || dir {
			key += "/"
		}
		if node.Children == nil {
			node.Children = map[string]*TreeDiffStats{}
		}
		child, ok := node.Children[key]
		if !ok {
			child = &TreeDiffStats{Path: node.Path + key}
			node.Children[key] = child
		}
		if isLast {
			child.BlobsAdded = stat.BlobsAdded
			child.BytesAdded = stat.BytesAdded
			child.BlobsRemoved = stat.BlobsRemoved
			child.BytesRemoved = stat.BytesRemoved
			child.BlobsCommon = stat.BlobsCommon
			child.BytesCommon = stat.BytesCommon
		}
		node = child
	}
}

func diffTreeStats(ctx context.Context, repo restic.Repository, id1, id2 restic.ID) (*TreeDiffStats, error) {
	paths1 := make(map[string]restic.BlobSet)
	paths2 := make(map[string]restic.BlobSet)
	if _, err := collectPathBlobs(ctx, repo, "/", id1, paths1); err != nil {
		return nil, err
	}
	if _, err := collectPathBlobs(ctx, repo, "/", id2, paths2); err != nil {
		return nil, err
	}

	uniq := make(map[string]struct{})
	for p := range paths1 {
		uniq[p] = struct{}{}
	}
	for p := range paths2 {
		uniq[p] = struct{}{}
	}

	list := slices.Collect(maps.Keys(uniq))
	sort.Strings(list)

	root := &TreeDiffStats{Path: "/", Children: map[string]*TreeDiffStats{}}

	if set1, ok := paths1["/"]; ok {
		stat := computeTreeStat(repo, set1, paths2["/"])
		root.BlobsAdded = stat.BlobsAdded
		root.BytesAdded = stat.BytesAdded
		root.BlobsRemoved = stat.BlobsRemoved
		root.BytesRemoved = stat.BytesRemoved
		root.BlobsCommon = stat.BlobsCommon
		root.BytesCommon = stat.BytesCommon
	}

	for _, p := range list {
		if p == "/" {
			continue
		}
		stat := computeTreeStat(repo, paths1[p], paths2[p])
		stat.Path = p
		insertTreeStat(root, &stat)
	}

	return root, nil
}

func blobCountSize(repo restic.Repository, set restic.BlobSet) (int, uint64) {
	var c int
	var b uint64
	for h := range set {
		c++
		size, found := repo.LookupBlobSize(h.Type, h.ID)
		if !found {
			Warnf("unable to find blob size for %v\n", h)
			continue
		}
		b += uint64(size)
	}
	return c, b
}

func (c *Comparer) diffTree(ctx context.Context, stats *DiffStatsContainer, prefix string, id1, id2 restic.ID) error {
	debug.Log("diffing %v to %v", id1, id2)
	tree1, err := restic.LoadTree(ctx, c.repo, id1)
	if err != nil {
		return err
	}

	tree2, err := restic.LoadTree(ctx, c.repo, id2)
	if err != nil {
		return err
	}

	tree1Nodes, tree2Nodes, names := uniqueNodeNames(tree1, tree2)

	for _, name := range names {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		node1, t1 := tree1Nodes[name]
		node2, t2 := tree2Nodes[name]

		addBlobs(stats.BlobsBefore, node1)
		addBlobs(stats.BlobsAfter, node2)

		switch {
		case t1 && t2:
			name := path.Join(prefix, name)
			mod := ""

			if node1.Type != node2.Type {
				mod += "T"
			}

			if node2.Type == restic.NodeTypeDir {
				name += "/"
			}

			if node1.Type == restic.NodeTypeFile &&
				node2.Type == restic.NodeTypeFile &&
				!reflect.DeepEqual(node1.Content, node2.Content) {
				mod += "M"
				stats.ChangedFiles++

				node1NilContent := *node1
				node2NilContent := *node2
				node1NilContent.Content = nil
				node2NilContent.Content = nil
				// the bitrot detection may not work if `backup --ignore-inode` or `--ignore-ctime` were used
				if node1NilContent.Equals(node2NilContent) {
					// probable bitrot detected
					mod += "?"
				}
			} else if c.opts.ShowMetadata && !node1.Equals(*node2) {
				mod += "U"
			}

			if mod != "" {
				c.printChange(NewChange(name, mod))
			}

			if node1.Type == restic.NodeTypeDir && node2.Type == restic.NodeTypeDir {
				var err error
				if (*node1.Subtree).Equal(*node2.Subtree) {
					err = c.collectDir(ctx, stats.BlobsCommon, *node1.Subtree)
				} else {
					err = c.diffTree(ctx, stats, name, *node1.Subtree, *node2.Subtree)
				}
				if err != nil && err != context.Canceled {
					Warnf("error: %v\n", err)
				}
			}
		case t1 && !t2:
			prefix := path.Join(prefix, name)
			if node1.Type == restic.NodeTypeDir {
				prefix += "/"
			}
			c.printChange(NewChange(prefix, "-"))
			stats.Removed.Add(node1)

			if node1.Type == restic.NodeTypeDir {
				err := c.printDir(ctx, "-", &stats.Removed, stats.BlobsBefore, prefix, *node1.Subtree)
				if err != nil && err != context.Canceled {
					Warnf("error: %v\n", err)
				}
			}
		case !t1 && t2:
			prefix := path.Join(prefix, name)
			if node2.Type == restic.NodeTypeDir {
				prefix += "/"
			}
			c.printChange(NewChange(prefix, "+"))
			stats.Added.Add(node2)

			if node2.Type == restic.NodeTypeDir {
				err := c.printDir(ctx, "+", &stats.Added, stats.BlobsAfter, prefix, *node2.Subtree)
				if err != nil && err != context.Canceled {
					Warnf("error: %v\n", err)
				}
			}
		}
	}

	return ctx.Err()
}

func runDiff(ctx context.Context, opts DiffOptions, gopts GlobalOptions, args []string) error {
	if len(args) != 2 {
		return errors.Fatalf("specify two snapshot IDs")
	}

	if opts.Tree {
		gopts.JSON = true
	}

	ctx, repo, unlock, err := openWithReadLock(ctx, gopts, gopts.NoLock)
	if err != nil {
		return err
	}
	defer unlock()

	// cache snapshots listing
	be, err := restic.MemorizeList(ctx, repo, restic.SnapshotFile)
	if err != nil {
		return err
	}
	sn1, subfolder1, err := loadSnapshot(ctx, be, repo, args[0])
	if err != nil {
		return err
	}

	sn2, subfolder2, err := loadSnapshot(ctx, be, repo, args[1])
	if err != nil {
		return err
	}

	if !gopts.JSON {
		Verbosef("comparing snapshot %v to %v:\n\n", sn1.ID().Str(), sn2.ID().Str())
	}
	bar := newIndexProgress(gopts.Quiet, gopts.JSON)
	if err = repo.LoadIndex(ctx, bar); err != nil {
		return err
	}

	if sn1.Tree == nil {
		return errors.Errorf("snapshot %v has nil tree", sn1.ID().Str())
	}

	if sn2.Tree == nil {
		return errors.Errorf("snapshot %v has nil tree", sn2.ID().Str())
	}

	sn1.Tree, err = restic.FindTreeDirectory(ctx, repo, sn1.Tree, subfolder1)
	if err != nil {
		return err
	}

	sn2.Tree, err = restic.FindTreeDirectory(ctx, repo, sn2.Tree, subfolder2)
	if err != nil {
		return err
	}

	if opts.Tree {
		stats, err := diffTreeStats(ctx, repo, *sn1.Tree, *sn2.Tree)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(globalOptions.stdout)
		if err := enc.Encode(stats); err != nil {
			return errors.Fatalf("JSON encode failed: %v", err)
		}
		return nil
	}

	c := &Comparer{
		repo: repo,
		opts: opts,
		printChange: func(change *Change) {
			Printf("%-5s%v\n", change.Modifier, change.Path)
		},
	}

	if gopts.JSON {
		enc := json.NewEncoder(globalOptions.stdout)
		c.printChange = func(change *Change) {
			err := enc.Encode(change)
			if err != nil {
				Warnf("JSON encode failed: %v\n", err)
			}
		}
	}

	if gopts.Quiet {
		c.printChange = func(_ *Change) {}
	}

	stats := &DiffStatsContainer{
		MessageType:    "statistics",
		SourceSnapshot: args[0],
		TargetSnapshot: args[1],
		BlobsBefore:    restic.NewBlobSet(),
		BlobsAfter:     restic.NewBlobSet(),
		BlobsCommon:    restic.NewBlobSet(),
	}
	stats.BlobsBefore.Insert(restic.BlobHandle{Type: restic.TreeBlob, ID: *sn1.Tree})
	stats.BlobsAfter.Insert(restic.BlobHandle{Type: restic.TreeBlob, ID: *sn2.Tree})

	err = c.diffTree(ctx, stats, "/", *sn1.Tree, *sn2.Tree)
	if err != nil {
		return err
	}

	both := stats.BlobsBefore.Intersect(stats.BlobsAfter)
	updateBlobs(repo, stats.BlobsBefore.Sub(both).Sub(stats.BlobsCommon), &stats.Removed)
	updateBlobs(repo, stats.BlobsAfter.Sub(both).Sub(stats.BlobsCommon), &stats.Added)

	if gopts.JSON {
		err := json.NewEncoder(globalOptions.stdout).Encode(stats)
		if err != nil {
			Warnf("JSON encode failed: %v\n", err)
		}
	} else {
		Printf("\n")
		Printf("Files:       %5d new, %5d removed, %5d changed\n", stats.Added.Files, stats.Removed.Files, stats.ChangedFiles)
		Printf("Dirs:        %5d new, %5d removed\n", stats.Added.Dirs, stats.Removed.Dirs)
		Printf("Others:      %5d new, %5d removed\n", stats.Added.Others, stats.Removed.Others)
		Printf("Data Blobs:  %5d new, %5d removed\n", stats.Added.DataBlobs, stats.Removed.DataBlobs)
		Printf("Tree Blobs:  %5d new, %5d removed\n", stats.Added.TreeBlobs, stats.Removed.TreeBlobs)
		Printf("  Added:   %-5s\n", ui.FormatBytes(stats.Added.Bytes))
		Printf("  Removed: %-5s\n", ui.FormatBytes(stats.Removed.Bytes))
	}

	return nil
}
