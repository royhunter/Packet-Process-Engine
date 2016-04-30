#ifndef __PLUGIN_H__
#define __PLUGIN_H__






typedef enum {
    PLUGIN_STREAMTCP,
    PLUGIN_SIZE,
}PluginId;


typedef struct {
    char *name;
    int (*Init)(void);
    int (*Func)(mbuf_t *m);
}PluginModule;








#endif
