package cxf

import (
	"encoding/base64"
	"sort"
	"strings"

	"github.com/nvinuesa/go-cxf"

	"github.com/nvinuesa/cxporter/internal/model"
)

// collectionNode represents a node in the collection tree.
type collectionNode struct {
	name     string
	items    []string // credential IDs
	children map[string]*collectionNode
}

// BuildCollections creates CXF Collection hierarchy from folder paths.
func BuildCollections(creds []model.Credential) []cxf.Collection {
	// Build tree structure from folder paths
	root := &collectionNode{
		name:     "",
		children: make(map[string]*collectionNode),
	}

	// Process each credential's folder path
	for i := range creds {
		cred := &creds[i]
		if cred.FolderPath == "" {
			continue
		}

		// Get credential ID
		credID := cred.ID
		if credID == "" {
			credID = generateBase64URLID()
		} else if !isBase64URL(credID) {
			credID = base64.RawURLEncoding.EncodeToString([]byte(credID))
		}

		// Parse folder path and add to tree
		parts := splitPath(cred.FolderPath)
		addToTree(root, parts, credID)
	}

	// Convert tree to CXF collections
	return treeToCollections(root)
}

// splitPath splits a folder path into parts.
func splitPath(path string) []string {
	// Normalize path separators
	path = strings.ReplaceAll(path, "\\", "/")

	// Remove leading/trailing slashes
	path = strings.Trim(path, "/")

	if path == "" {
		return nil
	}

	// Split by /
	parts := strings.Split(path, "/")

	// Filter empty parts
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}

	return result
}

// addToTree adds a credential ID to the tree at the specified path.
func addToTree(node *collectionNode, parts []string, credID string) {
	if len(parts) == 0 {
		return
	}

	// Get or create child node
	childName := parts[0]
	child, ok := node.children[childName]
	if !ok {
		child = &collectionNode{
			name:     childName,
			children: make(map[string]*collectionNode),
		}
		node.children[childName] = child
	}

	if len(parts) == 1 {
		// This is the target folder, add credential
		child.items = append(child.items, credID)
	} else {
		// Continue down the tree
		addToTree(child, parts[1:], credID)
	}
}

// treeToCollections converts the tree to CXF collections.
func treeToCollections(node *collectionNode) []cxf.Collection {
	if len(node.children) == 0 {
		return nil
	}

	// Get sorted child names for consistent output
	names := make([]string, 0, len(node.children))
	for name := range node.children {
		names = append(names, name)
	}
	sort.Strings(names)

	collections := make([]cxf.Collection, 0, len(names))
	for _, name := range names {
		child := node.children[name]
		collection := nodeToCollection(child)
		collections = append(collections, collection)
	}

	return collections
}

// nodeToCollection converts a tree node to a CXF Collection.
func nodeToCollection(node *collectionNode) cxf.Collection {
	// Build linked items
	linkedItems := make([]cxf.LinkedItem, len(node.items))
	for i, itemID := range node.items {
		linkedItems[i] = cxf.LinkedItem{
			Item: itemID,
		}
	}

	// Build sub-collections
	var subCollections []cxf.Collection
	if len(node.children) > 0 {
		subCollections = treeToCollections(node)
	}

	return cxf.Collection{
		ID:             generateBase64URLID(),
		Title:          node.name,
		Items:          linkedItems,
		SubCollections: subCollections,
	}
}
