/* ssh-honeypot -- by Daniel Roberson (daniel(a)planethacker.net) 2016-2019 
*  Modified by Coder014 2021
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>
#include <syslog.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <libssh/libssh.h>
#include <libssh/server.h>

#include "config.h"


/* Globals */
char *          logfile             = NULL;
char *          rsakey              = RSAKEY;
char *          bindaddr            = BINDADDR;
const char *    joke                = JOKE;
bool            use_syslog          = false;
bool            logging             = false;
bool            verbose             = false;
char            hostname[MAXHOSTNAMELEN];
FILE*		    fp		            = NULL;


/* Banners */
static struct banner_info_s {
  const char	*str, *info;
} banners[] = {
  {"",  "No banner"},
  {"OpenSSH_5.9p1 Debian-5ubuntu1.4", "Ubuntu 12.04"},
  {"OpenSSH_7.2p2 Ubuntu-4ubuntu2.1", "Ubuntu 16.04"},
  {"OpenSSH_7.6p1 Ubuntu-4ubuntu0.3", "Ubuntu 18.04"},
  {"OpenSSH_6.6.1",                   "openSUSE 42.1"},
  {"OpenSSH_6.7p1 Debian-5+deb8u3",   "Debian 8.6"},
  {"OpenSSH_7.5",                     "pfSense 2.4.4-RELEASE-p3"},
  {"dropbear_2014.63",                "dropbear 2014.63"},
};

const size_t num_banners = sizeof banners / sizeof *banners;


/* usage() -- prints out usage instructions and exits the program
 */
static void usage (const char *progname) {
  fprintf (stderr, "ssh-honeypot %s by %s\n\n", VERSION, AUTHOR);

  fprintf (stderr, "usage: %s "
	   "[-?h -p <port> -a <address> -i <index> -l <file> -r <file> "
	   "-f <file> -u <user>]\n",
	   progname);
  fprintf (stderr, "\t-?/-h\t\t-- this help menu\n");
  fprintf (stderr, "\t-p <port>\t-- listen port\n");
  fprintf (stderr, "\t-a <address>\t-- IP address to bind to\n");
  fprintf (stderr, "\t-l <file>\t-- log file\n");
  fprintf (stderr, "\t-s\t\t-- toggle syslog usage. Default: %s\n",
	   use_syslog ? "on" : "off");
  fprintf (stderr, "\t-r <file>\t-- specify RSA key to use. Default: %s\n",
	   rsakey);
  fprintf (stderr, "\t-b\t\t-- list available banners\n");
  fprintf (stderr, "\t-b <string>\t-- specify banner string (max 255 characters)\n");
  fprintf (stderr, "\t-i <index>\t-- specify banner index\n");
  fprintf (stderr, "\t-j <string>\t-- specify joke string (max 255 characters)\n");
  fprintf (stderr, "\t-u <user>\t-- user to setuid() to after bind()\n");
  fprintf (stderr, "\t-v\t-- verbose log output\n");

  exit (EXIT_FAILURE);
}


/* pr_banners() -- prints out a list of available banner options
 */
static void pr_banners () {
  fprintf (stderr, "Available banners: [index] banner (description)\n");

  for (size_t i = 0; i < num_banners; i++) {
    struct banner_info_s *banner = banners + i;
    fprintf (stderr, "[%zu] %s (%s)\n", i, banner->str, banner->info);
  }

  fprintf (stderr, "Total banners: %zu\n", num_banners);
}


/* log_entry() -- adds timestamped log entry
 *             -- displays output to stdout if logging is false
 */
static void log_entry (const char *fmt, ...) {
  time_t	t;
  va_list	va;
  char *	timestr;
  char		buf[1024];


  time (&t);
  timestr = strtok (ctime (&t), "\n"); // banish newline character to the land
                                       // of wind and ghosts

  va_start (va, fmt);
  vsnprintf (buf, sizeof(buf), fmt, va);
  va_end (va);

 if (logging) {
    fprintf (fp, "[%s] %s\n", timestr, buf);
    fflush(fp);
 }
 else if (use_syslog) {
    syslog (LOG_INFO, "%s", buf);
 }
 else {
    printf ("[%s] %s\n", timestr, buf);
	fflush(stdout);
 }
}


/* log_entry_fatal() -- log a message, then exit with EXIT_FAILURE
 */
void log_entry_fatal (const char *fmt, ...) {
  log_entry (fmt);

  exit (EXIT_FAILURE);
}


/* get_ssh_ip() -- obtains IP address via ssh_session
 */
static char *get_ssh_ip (ssh_session session) {
  static char			ip[INET6_ADDRSTRLEN];
  struct sockaddr_storage	tmp;
  struct in_addr		*inaddr;
  struct in6_addr		*in6addr;
  socklen_t			address_len = sizeof(tmp);


  getpeername (ssh_get_fd (session), (struct sockaddr *)&tmp, &address_len);
  inaddr = &((struct sockaddr_in *)&tmp)->sin_addr;
  in6addr = &((struct sockaddr_in6 *)&tmp)->sin6_addr;
  inet_ntop (tmp.ss_family, tmp.ss_family==AF_INET?(void*)inaddr:(void*)in6addr,
	     ip, sizeof(ip));

  return ip;
}

static bool check_pw(const char *user, const char *password){
    if(strcmp(user,"root"))
        return 0;
    if(strcmp(password,"root"))
        return 0;
    return 1; // authenticated
}

/* handle_ssh_auth() -- handles ssh authentication requests, logging
 *                   -- appropriately.
 */
static bool handle_ssh_auth (ssh_session session) {
  ssh_message	message;
  char *	ip;


  ip = get_ssh_ip (session);

  if (ssh_handle_key_exchange (session)) {
    if (verbose)
      log_entry ("%s Error exchanging keys: %s", ip, ssh_get_error (session));

    return -1;
  }
  ssh_set_auth_methods(session, SSH_AUTH_METHOD_PASSWORD);

  char *banner_c   = (char *)ssh_get_clientbanner (session);
  char *banner_s   = (char *)ssh_get_serverbanner (session);
  char *kex_algo   = (char *)ssh_get_kex_algo (session);
  char *cipher_in  = (char *)ssh_get_cipher_in (session);
  char *cipher_out = (char *)ssh_get_cipher_out (session);
  char *hmac_in    = (char *)ssh_get_hmac_in (session);
  char *hmac_out   = (char *)ssh_get_hmac_out (session);

  if (verbose)
    log_entry ("Session:  %s|%s|%s|%s|%s|%s|%s",
  	     banner_c,
  	     banner_s,
  	     kex_algo,
  	     cipher_in,
  	     cipher_out,
  	     hmac_in,
  	     hmac_out);

  bool authed = false;
  for (int i=0; i<5;) {
    if ((message = ssh_message_get (session)) == NULL)
      break;

    switch (ssh_message_subtype (message)) {
    case SSH_AUTH_METHOD_PASSWORD:
      i++;
      log_entry ("%s %s %s",
		 ip,
		 ssh_message_auth_user (message),
		 ssh_message_auth_password (message));
	  if(check_pw(ssh_message_auth_user(message),
		ssh_message_auth_password(message))){
		  authed=true;
		  ssh_message_auth_reply_success(message,0);
	  }
      break;
    }

	if(authed) {
		ssh_message_free(message);
		break;
	}

    ssh_message_reply_default(message);
    ssh_message_free(message);
  }

  if(authed){
  ssh_channel chan=NULL;
  do {
        message=ssh_message_get(session);
        if(message){
            switch(ssh_message_type(message)){
                case SSH_REQUEST_CHANNEL_OPEN:
                    if(ssh_message_subtype(message)==SSH_CHANNEL_SESSION){
                        chan=ssh_message_channel_request_open_reply_accept(message);
                        break;
                    }
                default:
                ssh_message_reply_default(message);
            }
            ssh_message_free(message);
        }
    } while(message && !chan);
  ssh_channel_write(chan, joke, strlen(joke));
  ssh_channel_send_eof(chan);
  ssh_channel_close(chan);
  ssh_channel_free(chan);
  }

  ssh_disconnect(session);
  ssh_free(session);
  return EXIT_SUCCESS;
}


/* drop_privileges() -- drops privileges to specified user/group
 */
void drop_privileges (char *username) {
  struct passwd *	pw;
  struct group *	grp;


  pw = getpwnam (username);
  if (pw == NULL)
    log_entry_fatal ("FATAL: Username does not exist: %s\n", username);

  grp = getgrgid (pw->pw_gid);
  if (grp == NULL)
    log_entry_fatal ("FATAL: Unable to determine groupfor %d: %s\n",
		     pw->pw_gid,
		     strerror (errno));

  /* chown logfile so this user can use it */
  if (logfile != NULL){
  if (chown (logfile, pw->pw_uid, pw->pw_gid) == -1)
    log_entry_fatal ("FATAL: Unable to set permissions for log file %s: %s\n",
		     logfile,
		     strerror (errno));
  }

  /* drop group first */
  if (setgid (pw->pw_gid) == -1)
    log_entry_fatal ("FATAL: Unable to drop group permissions to %s: %s\n",
		     grp->gr_name,
		     strerror (errno));

  /* drop user privileges */
  if (setuid (pw->pw_uid) == -1)
    log_entry_fatal ("FATAL: Unable to drop user permissions to %s: %s\n",
		     username,
		     strerror (errno));
}


/* main() -- main entry point of program
 */
int main (int argc, char *argv[]) {
  pid_t			child;
  int			opt;
  unsigned short	port = PORT, banner_index = 1;
  const char *		banner = banners[banner_index].str;
  char *		username = NULL;
  ssh_session		session;
  ssh_bind		sshbind;


  while ((opt = getopt (argc, argv, "vh?p:l:a:b:i:r:su:i:j:")) != -1) {
    switch (opt) {
    case 'p': /* Listen port */
      port = atoi(optarg);
      break;

    case 'l': /* Log file path */
      logfile = optarg;
      logging = true;
      break;

    case 'a': /* IP to bind to */
      bindaddr = optarg;
      break;

    case 'r': /* Path to RSA key */
      rsakey = optarg;
      break;

    case 's': /* Toggle syslog */
      use_syslog = use_syslog ? false : true;
      break;

    case 'u': /* User to drop privileges to */
      username = optarg;
      break;

    case 'i': /* Set banner by index */
      banner_index = atoi(optarg);

      if (banner_index >= num_banners) {
          fprintf (stderr, "FATAL: Invalid banner index\n");
          exit (EXIT_FAILURE);
      }

      banner = banners[banner_index].str;
      break;

    case 'b': /* Specify banner string */
      banner = optarg;
      break;

	case 'j': /* Specify joke string */
	  joke = optarg;
	  break;

    case '?': /* Print usage */
    case 'h':
      if (optopt == 'i' || optopt == 'b') {
        pr_banners();
        return EXIT_SUCCESS;
      }
      usage (argv[0]);
      return EXIT_SUCCESS;

    case 'v': /* verbose output */
      verbose = true;
      break;

    default:
      usage (argv[0]);
    }
  }

  if (logging) {
    if ((fp = fopen (logfile, "a+")) == NULL) {
      fprintf (stderr, "Unable to open logfile %s: %s\n",
               logfile,
               strerror (errno));
      exit (EXIT_FAILURE);
    }
  }

  if (gethostname (hostname, sizeof(hostname)) == -1)
    log_entry_fatal ("FATAL: gethostname(): %s\n", strerror (errno));

  signal (SIGCHLD, SIG_IGN);

  log_entry ("ssh-honeypot %s by %s started on port %d. PID %d",
	     VERSION,
	     AUTHOR,
	     port,
	     getpid());

  session = ssh_new ();
  sshbind = ssh_bind_new ();

  ssh_bind_options_set (sshbind, SSH_BIND_OPTIONS_BINDADDR, bindaddr);
  ssh_bind_options_set (sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);
  ssh_bind_options_set (sshbind, SSH_BIND_OPTIONS_BANNER, banner);
  ssh_bind_options_set (sshbind, SSH_BIND_OPTIONS_RSAKEY, rsakey);

  if (ssh_bind_listen (sshbind) < 0) {
    log_entry_fatal ("FATAL: ssh_bind_listen(): %s", ssh_get_error (sshbind));
  }

  /* drop privileges */
  if (username != NULL)
    drop_privileges (username);

  setsid();
  for (;;) {
    if (ssh_bind_accept (sshbind, session) == SSH_ERROR)
      log_entry_fatal ("FATAL: ssh_bind_accept(): %s", ssh_get_error (sshbind));

    child = fork();

    if (child < 0)
      log_entry_fatal ("FATAL: fork(): %s", strerror (errno));

    if (child == 0)
      exit (handle_ssh_auth (session));
  }

  return EXIT_SUCCESS;
}
