/*
 * Small Graphviz-compatible state graph used by the artifact build.
 *
 * The research tool only needs a directed graph and DOT export.  Keeping this
 * implementation local avoids requiring the full Graphviz development package
 * on a reviewer's machine while preserving AFLNet's state-machine output.
 */
#ifndef ARTIFACT_GRAPHVIZ_GVC_H
#define ARTIFACT_GRAPHVIZ_GVC_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define Agdirected 1
#define AGNODE 1
#define AGEDGE 2
#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif

typedef struct artifact_edge Agedge_t;
typedef struct artifact_node Agnode_t;
typedef struct artifact_graph Agraph_t;

struct artifact_node {
  char *name;
  char *color;
};

struct artifact_edge {
  Agnode_t *from;
  char *color;
  Agnode_t *to;
};

struct artifact_graph {
  Agnode_t **nodes;
  size_t node_count;
  Agedge_t **edges;
  size_t edge_count;
};

static inline Agraph_t *agopen(const char *name, int kind, void *disc) {
  (void)name; (void)kind; (void)disc;
  return (Agraph_t *)calloc(1, sizeof(Agraph_t));
}

static inline void *agattr(Agraph_t *g, int kind, const char *name,
                           const char *value) {
  (void)g; (void)kind; (void)name; (void)value; return NULL;
}

static inline Agnode_t *agnode(Agraph_t *g, const char *name, int create) {
  size_t i;
  if (!g || !name) return NULL;
  for (i = 0; i < g->node_count; ++i)
    if (!strcmp(g->nodes[i]->name, name)) return g->nodes[i];
  if (!create) return NULL;
  Agnode_t *n = (Agnode_t *)calloc(1, sizeof(*n));
  if (!n) return NULL;
  n->name = strdup(name);
  g->nodes = (Agnode_t **)realloc(g->nodes,
                                  (g->node_count + 1) * sizeof(*g->nodes));
  g->nodes[g->node_count++] = n;
  return n;
}

static inline Agedge_t *agedge(Agraph_t *g, Agnode_t *from, Agnode_t *to,
                               const char *name, int create) {
  (void)name;
  size_t i;
  if (!g || !from || !to) return NULL;
  for (i = 0; i < g->edge_count; ++i)
    if (g->edges[i]->from == from && g->edges[i]->to == to)
      return g->edges[i];
  if (!create) return NULL;
  Agedge_t *e = (Agedge_t *)calloc(1, sizeof(*e));
  if (!e) return NULL;
  e->from = from; e->to = to;
  g->edges = (Agedge_t **)realloc(g->edges,
                                  (g->edge_count + 1) * sizeof(*g->edges));
  g->edges[g->edge_count++] = e;
  return e;
}

static inline int agset(void *obj, const char *name, const char *value) {
  if (!obj || !name || !value || strcmp(name, "color")) return 0;
  /* Node and edge layouts intentionally share color at the same offset. */
  char **slot = (char **)((char *)obj + sizeof(void *));
  free(*slot); *slot = strdup(value); return 0;
}

static inline int agwrite(Agraph_t *g, FILE *fp) {
  size_t i;
  if (!g || !fp) return -1;
  fputs("digraph ipsm {\n", fp);
  for (i = 0; i < g->node_count; ++i)
    fprintf(fp, "  \"%s\" [color=\"%s\"];\n", g->nodes[i]->name,
            g->nodes[i]->color ? g->nodes[i]->color : "black");
  for (i = 0; i < g->edge_count; ++i)
    fprintf(fp, "  \"%s\" -> \"%s\" [color=\"%s\"];\n",
            g->edges[i]->from->name, g->edges[i]->to->name,
            g->edges[i]->color ? g->edges[i]->color : "black");
  fputs("}\n", fp); return 0;
}

static inline int agnnodes(Agraph_t *g) { return g ? (int)g->node_count : 0; }
static inline int agnedges(Agraph_t *g) { return g ? (int)g->edge_count : 0; }

static inline int agclose(Agraph_t *g) {
  size_t i;
  if (!g) return 0;
  for (i = 0; i < g->node_count; ++i) {
    free(g->nodes[i]->name); free(g->nodes[i]->color); free(g->nodes[i]);
  }
  for (i = 0; i < g->edge_count; ++i) {
    free(g->edges[i]->color); free(g->edges[i]);
  }
  free(g->nodes); free(g->edges); free(g); return 0;
}

#endif
