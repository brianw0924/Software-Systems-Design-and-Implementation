// SPDX-License-Identifier: BSD-3-Clause
#include <linux/kernel.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

#define N_commands 3
#define N_args 2
#define _POSIX_ARG_MAX 4096
#define Delimiter " \n"

char *input = NULL;
char **args = NULL;
long input_buf = 0;
int getcpu();
int my_cd();
int my_exit();
int my_execute();
void tokenize();


char *commands_str[] = {
	"getcpu",
	"cd",
	"exit",
};

int (*commands_func[]) () = {
	&getcpu,
	&my_cd,
	&my_exit
};

int getcpu()
{
	if (args[1] != NULL) {
		fprintf(stderr, "error: Too many arguments.\n");
		return 1;
	}
	long ret = syscall(436);

	if (ret >= 0)
		printf("%ld\n", ret);
	else
		fprintf(stderr, "error: %s\n", strerror(errno));
	return 1;
}

int my_cd()
{

	if (args[1] == NULL) {
		fprintf(stderr, "error: Missing argument.\n");
		return 1;
	}

	if (args[2] != NULL) {
		fprintf(stderr, "error: Too many arguments.\n");
		return 1;
	}

	if (chdir(args[1]) != 0)
		return -1;

	return 1;
}

int my_exit()
{
	if (args[1] != NULL) {
		fprintf(stderr, "error: Too many arguments.\n");
		return 1;
	}
	return 0;
}

int my_execute()
{


	pid_t pid, wpid;
	int status;

	pid = fork();
	if (pid == 0) {
		/* Child */
		if (execv(args[0], args) == -1)
			fprintf(stderr, "error: %s\n", strerror(errno));
		free(args);
		args = NULL;
		free(input);
		input = NULL;
		input_buf = 0;
		exit(EXIT_FAILURE);
	} else {
		/* Parent */
		do {
			wpid = waitpid(pid, &status, WUNTRACED);
		} while (!WIFEXITED(status) && !WIFSIGNALED(status));
	}

	return 1;
}

int run_command()
{
	for (int i = 0; i < N_commands; i++) {
		if (strcmp(args[0], commands_str[i]) == 0)
			return (*commands_func[i])(args);
	}

	return my_execute(args);
}

void tokenize()
{
	char *token;
	int next_token_position = 0;

	token = strtok(input, Delimiter);

	while (token != NULL) {
		args[next_token_position++] = token;
		token = strtok(NULL, Delimiter);
		if (next_token_position > _POSIX_ARG_MAX)
			fprintf(stderr, "error: Number of arguments limit exceeded.\n");
	}
	args[next_token_position] = NULL;

}

void signal_handler(int signum) {
    if (signum == SIGINT) {
	if(input) free(input);
	if(args) free(args);
        exit(1);
    }
}


int main(int argc, char **argv)
{
	int status;

	if (signal(SIGINT, signal_handler) == SIG_ERR) 
		fprintf(stderr, "error: %s\n", strerror(errno));


	while (1) {
		printf("$");

		if (getline(&input, &input_buf, stdin) > 1) {
			args = malloc((_POSIX_ARG_MAX+1) * sizeof(char *));
			tokenize();
			status = run_command();

			free(args);
			args = NULL;
			free(input);
			input = NULL;
			input_buf = 0;

			if (status == 0)
				break;
			else if (status == -1)
				fprintf(stderr, "error: %s\n", strerror(errno));
		}
	}
	return EXIT_SUCCESS;
}
