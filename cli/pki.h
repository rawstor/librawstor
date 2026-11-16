#ifndef RAWSTOR_CLI_PKI_H
#define RAWSTOR_CLI_PKI_H

#ifdef __cplusplus
extern "C" {
#endif

/* `rawstor pki <subcommand> ...`: argv[0] is "pki". It never needs TLS or
 * rawstor_initialize(): it makes the certificates a process needs for it. */
int rawstor_cli_pki(int argc, char** argv);

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_CLI_PKI_H
