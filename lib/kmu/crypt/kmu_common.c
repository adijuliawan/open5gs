#include "kmu_common.h"

char *kmu_id_get_value(const char *str)
{
    char *token, *p, *tmp;
    char *ueid = NULL;

    tmp = strdup(str);
    if (!tmp) {
        error(1, errno, "strdup failed");
        goto cleanup;
    }

    p = tmp;

    token = strsep(&p, "-");
    if (!token) {
        error(1, errno, "strsep failed");
        goto cleanup;
    }
    token = strsep(&p, "-");
    if (!token) {
        error(1, errno, "strsep failed");
        goto cleanup;
    }
    ueid = strdup(token);
    if (!ueid) {
        error(1, errno, "strdup failed");
        goto cleanup;
    }

cleanup:
    if (tmp)
        free(tmp);
    return ueid;
}