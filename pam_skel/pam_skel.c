#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define CHARADAS_FILE "/etc/security/charadas.txt"
#define MAX_LINE 512
#define MAX_QUESTION 256
#define MAX_ANSWER 256
#define MAX_CHARADAS 50

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    FILE *fp;
    char line[MAX_LINE];
    char *questions[MAX_CHARADAS];
    char *answers[MAX_CHARADAS];
    int count = 0;

    fp = fopen(CHARADAS_FILE, "r");
    if (!fp) {
        pam_syslog(pamh, LOG_ERR, "Não foi possível abrir o arquivo de charadas.");
        return PAM_AUTH_ERR;
    }

    while (fgets(line, sizeof(line), fp) != NULL && count < MAX_CHARADAS) {
        char *sep = strchr(line, '|');
        if (sep) {
            *sep = '\0';
            questions[count] = strdup(line);
            answers[count] = strdup(sep + 1);
            answers[count][strcspn(answers[count], "\n")] = '\0';
            count++;
        }
    }
    fclose(fp);

    if (count == 0) {
        pam_syslog(pamh, LOG_ERR, "Nenhuma charada encontrada.");
        return PAM_AUTH_ERR;
    }

    srand(time(NULL));
    int index = rand() % count;

    const struct pam_message msg = {
        .msg_style = PAM_PROMPT_ECHO_ON,
        .msg = questions[index]
    };
    const struct pam_message *msgp = &msg;
    struct pam_response *resp = NULL;
    const struct pam_conv *conv;

    if (pam_get_item(pamh, PAM_CONV, (const void **)&conv) != PAM_SUCCESS || !conv) {
        return PAM_AUTH_ERR;
    }

    if (conv->conv(1, &msgp, &resp, conv->appdata_ptr) != PAM_SUCCESS || !resp || !resp->resp) {
        return PAM_AUTH_ERR;
    }

    if (strcasecmp(resp->resp, answers[index]) != 0) {
        pam_syslog(pamh, LOG_NOTICE, "Charada respondida incorretamente.");
        free(resp->resp);
        return PAM_AUTH_ERR;
    }

    free(resp->resp);
    return PAM_SUCCESS;
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}