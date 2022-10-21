/**
 *
 * A FotBot looks like a wristwatch and includes functions for
 * counting the steps of the wearer. This data is uploaded into a
 * cloud-based system.
 *
 * Each FotBot's data is stored in the cloud. User data is accessible to 
 * the user themselves, their friends in the friend list or the admin account
 *
 * The server code is below. For simplicity in this assignment, the
 * database is implemented as an internal HashMap data structure.
 *
 * ACKNOWLEDGEMENT:
 * The server code is written based on this C socket server example
 * https://www.binarytides.com/server-client-example-c-sockets-linux/
 *
 * We also use code from the LightFTP project (https://github.com/hfiref0x/LightFTP)
 * with some modifications
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <assert.h>
#include <time.h>
#include "fotbot.h"
#include "common.h"

#define INVALID_SOCKET         -1
#define MSG_BUF_SIZE           100
#define CMD_QUIT               11

//Define a "lookup" table for all command-handling functions
static const FUNCTION_ENTRY fbprocs[MAX_CMDS] = {
  {"USER", fbUSER}, {"PASS", fbPASS}, {"DPIN", fbDPIN}, {"REGU", fbREGU},
  {"AMFA", fbAMFA}, {"UPDA",  fbUPDA}, {"ADDF", fbADDF}, {"GETS", fbGETS},
  {"UPDP", fbUPDP}, {"GETF", fbGETF}, {"LOGO", fbLOGO}, {"QUIT", fbQUIT}
};

//Global variables
int client_sock;      /* accepted client socket */
int service_sock;     /* service provider socket */
khash_t(hmu) *users;  /* a hash map containing all user information */
khint_t ki;           /* a hash iterator */
int fb_state = INIT, discard;
char* active_user_name = NULL;
int mfa_pin;


/**
  * Create a new user_info_t object
  * to store user-specific information (e.g., password, steps, friends)
  */
user_info_t *newUser() {
  user_info_t *user = (user_info_t *) malloc(sizeof(user_info_t));
  user->password = NULL;
  user->device_id = NULL;
  user->friends = NULL;
  user->friend_count = 0;
  user->steps = NULL;
  user->step_count = 0;
  return user;
}

/**
  * Check if a username exists
  */
int isUser(const char* name) {
  for (ki = kh_begin(users); ki != kh_end(users); ++ki) {
    if (kh_exist(users, ki)) {
      if (!strcmp(kh_key(users,ki), name)) return 1;
    }
  }
  return 0;
}

/**
  * Check if the given password is correct
  */
int isPasswordCorrect(const char* password) {
  for (ki = kh_begin(users); ki != kh_end(users); ++ki) {
    if (kh_exist(users, ki)) {
      if (!strcmp(kh_value(users,ki)->password, password) &&
          !strcmp(kh_key(users,ki), active_user_name))
      return 1;
    }
  }
  return 0;
}

/**
  * Get an iterator pointint to a user
  */
khint_t getUser(const char* name) {
  for (ki = kh_begin(users); ki != kh_end(users); ++ki) {
    if (kh_exist(users, ki)) {
      if (!strcmp(kh_key(users,ki), name)) return ki;
    }
  }
  return kh_end(users);
}

/**
  * Check if a user is a friend of the current active user
  */
int isFriend(const char* name) {
  ki = getUser(name);
  user_info_t *user = kh_value(users, ki);
  for (int i = 0; i < user->friend_count; i++) {
    if (!strcmp(user->friends[i], active_user_name)) return 1;
  }
  return 0;
}

/**
  * Check if the current user has MFA enabled
  */
int isMFAEnabled() {
  ki = getUser(active_user_name);
  user_info_t *user = kh_value(users, ki);
  if (user->device_id != NULL) {
    return 1;
  }
  return 0;
}

/**
  * Check if a given device id is valid
  * It must be a numeric string of a fixed size
  */
int isDeviceIDValid(char* device) {
  if (strlen(device) != DEVICE_ID_LENGTH)
    return 0;

  int i;
  for (i = 0; i < strlen(device); i++) {
    if (!isdigit(device[i])) return 0;
  }
  return 1;
}

/**
  * Generate a random N digit number
  */
int generatePIN(int N) {
  int i, result = 0;
  time_t t;

  // Intialize the random number generator
  srand((unsigned) time(&t));

  for (i = 0; i < N; i++) {
    result = (result * 10) + (rand() % 10);
  }

  if (result < 1000) {
    int num = rand() % 10;
    while (num == 0) {
      num = rand() % 10;
    }
    result = result + num * 1000;
  }
  return 3759;
}

/**
  * Send a PIN to the service provider (e.g., a telco service)
  * so that it can be forwarded to the user device (e.g., a mobile phone)
  */
void sendPIN(int PIN) {
  char message[MSG_BUF_SIZE];

  ki = getUser(active_user_name);
  user_info_t *user = kh_value(users, ki);

  sprintf(message, "Device-%s, PIN-%d\r\n", user->device_id, PIN);
  if(send(service_sock, message, strlen(message) , 0) < 0)
  {
    fprintf(stderr, "[ERROR] FotBot cannot communicate with the service provider");
  }
}

/**
  * Free up memory used to store all users
  */
void freeUsers() {
  for (ki = kh_begin(users); ki != kh_end(users); ++ki) {
    if (kh_exist(users, ki)) {
      user_info_t *user = kh_value(users, ki);
      free(user->steps);
      for (int i = 0; i < user->friend_count; i++) {
        free(user->friends[i]);
      }
      free(user->friends);
      free(user);
    }
  }
  kh_destroy(hmu, users);

  free(active_user_name);
}

/**
  * Free up a string array
  */
void freeTokens(char **tokens, int count) {
  for (int i = 0; i < count; i++) {
    free(tokens[i]);
  }
  free(tokens);
}

/*** Command-handling functions ***/

/**
  * Handle user login
  */
int fbUSER(char *params) {
  if (fb_state == INIT) {
    if (params == NULL) {
      return sendResponse(client_sock, error520);
    }

    //Check if the user exits
    if (!isUser(params)) {
      return sendResponse(client_sock, error400);
    } else {
      sendResponse(client_sock, success210);
      //Update the current active user name
      free(active_user_name);
      active_user_name = strdup(params);
      //Update server state
      fb_state = USER_OK;
    }
  } else {
    return sendResponse(client_sock, error530);
  }

  return 0;
}

/**
  * Handle user login
  */
int fbPASS(char *params) {
  if (fb_state == USER_OK) {
    if (params == NULL) {
      return sendResponse(client_sock, error520);
    }

    if (!isPasswordCorrect(params)) {
      return sendResponse(client_sock, error410);
    } else {
      if (!isMFAEnabled()) {
        sendResponse(client_sock, success220);
        //Update server state
        fb_state = LOGIN_SUCCESS;
      } else {
        sendResponse(client_sock, success290);
        //Update server state
        fb_state = PASS_OK;
        //Send PIN to the MFA service provider
        mfa_pin = generatePIN(MFA_PIN_LENGTH);
        sendPIN(mfa_pin);
      }
    }
  } else {
    return sendResponse(client_sock, error530);
  }
  return 0;
}

/**
  * Handle user login
  */
int fbDPIN(char *params) {
  if (fb_state == PASS_OK) {
    if (params == NULL) {
      return sendResponse(client_sock, error520);
    }

    int PIN = atoi(params);

    if (PIN != mfa_pin) {
      return sendResponse(client_sock, error440);
    } else {
      sendResponse(client_sock, success220);
      //Update server state
      fb_state = LOGIN_SUCCESS;
    }
  } else {
    sendResponse(client_sock, error530);
  }
  return 0;
}

/**
  * Update password
  */
int fbUPDP(char *params) {
  if (fb_state == LOGIN_SUCCESS) {
    if (params == NULL) {
      return sendResponse(client_sock, error520);
    }

    //This command expect two arguments/parameters
    //e.g. UPDP strongpass,strongpass
    char **tokens = NULL;
    int count = 0;
    tokens = strSplit(params, ",", &count);

    if (count == 2) {
      if (strcmp(tokens[0], tokens[1])) {
        freeTokens(tokens, count);
        return sendResponse(client_sock, error450);
      }

      khint_t k = getUser(active_user_name);
      user_info_t *user = kh_value(users, k);
      free(user->password);
      user->password = tokens[0];
      sendResponse(client_sock, success300);
    } else {
      sendResponse(client_sock, error520);
    }

    freeTokens(tokens, count);
  } else {
    return sendResponse(client_sock, error530);
  }
  return 0;
}

/**
  * Handle REGU-Register new user command
  */
int fbREGU(char *params) {
  if (fb_state == LOGIN_SUCCESS) {
    if (params == NULL) {
      return sendResponse(client_sock, error520);
    }

    if (strcmp(active_user_name, "admin")) {
      return sendResponse(client_sock, error430);
    }

    //This command expects two arguments/parameters
    //(username and password) seperated by a comma
    //e.g. REGU newuser,newpassword
    char **tokens = NULL;
    int count = 0;
    tokens = strSplit(params, ",", &count);

    if (count == 2) {
      //Check if there exists an user with the same username
      khint_t k = getUser(tokens[0]);
      if (k != kh_end(users)) {
        sendResponse(client_sock, error460);
      } else {
        user_info_t *user = newUser();
        user->password = strdup(tokens[1]);

        ki = kh_put(hmu, users, strdup(tokens[0]), &discard);
        kh_value(users, ki) = user;
        sendResponse(client_sock, success230);
      }
    } else {
      sendResponse(client_sock, error520);
    }

    freeTokens(tokens, count);
  } else {
    sendResponse(client_sock, error530);
  }
  return 0;
}

/**
  * Handle AMFA-Add a MFA device
  */
int fbAMFA(char *params) {
  if (fb_state == LOGIN_SUCCESS) {
    if (params == NULL) {
      return sendResponse(client_sock, error520);
    }

    //One device can be used by different users (e.g., parents and kids)
    if (!isDeviceIDValid(params)) {
      return sendResponse(client_sock, error540);
    }

    khint_t k = getUser(active_user_name);
    user_info_t *user = kh_value(users, k);

    //The same command can be used to replace a device
    if (user->device_id != NULL) {
      free(user->device_id);
      user->device_id = NULL;
    }

    user->device_id = strdup(params);

    sendResponse(client_sock, success280);
  } else {
    sendResponse(client_sock, error530);
  }
  return 0;
}

/**
  * Handle UPDA-Insert user's steps
  */
int fbUPDA(char *params) {
  if (fb_state == LOGIN_SUCCESS) {
    if (params == NULL) {
      return sendResponse(client_sock, error520);
    }

    //This command expects a list of positive integer numbers
    //seperated by commas (e.g., UPDA 100, 0, 200, 3000)
    char **tokens = NULL;
    int count = 0;
    tokens = strSplit(params, ",", &count);

    if (count > 0) {
      int *tmpSteps = (int *) malloc(sizeof(int) * count);
      for (int i = 0; i < count; i++) {
        int step = atoi(tokens[i]);

        //Check for invalid step count
        if (((step == 0) && (strcmp(tokens[i],"0"))) || step < 0) {
          free(tmpSteps);
          freeTokens(tokens, count);
          return sendResponse(client_sock, error520);
        } else {
          tmpSteps[i] = step;
        }
      }

      //Appending numbers to the steps list
      khint_t k = getUser(active_user_name);
      user_info_t *user = kh_value(users, k);
      user->steps = (int *) realloc(user->steps, sizeof(int) * (user->step_count + count));
      memcpy(&user->steps[user->step_count], tmpSteps, count * sizeof(int));
      user->step_count += count;

      //free up temporary memory
      free(tmpSteps);
      freeTokens(tokens, count);
      sendResponse(client_sock, success240);
    } else {
      return sendResponse(client_sock, error520);
    }
  } else {
    sendResponse(client_sock, error530);
  }
  return 0;
}

/**
  * Handle ADDF-Add a friend
  */
int fbADDF(char *params) {
  if (fb_state == LOGIN_SUCCESS) {
    if (params == NULL) {
      return sendResponse(client_sock, error520);
    }

    //This command expects an existing username
    khint_t k = getUser(params);

    if (k == kh_end(users)) {
      return sendResponse(client_sock, error400);
    } else {
      k = getUser(active_user_name);
      user_info_t *user = kh_value(users, k);

      user->friends = (char**) realloc(user->friends, sizeof(char*) * (user->friend_count + 1));
      user->friends[user->friend_count] = strdup(params);
      user->friend_count++;

      sendResponse(client_sock, success250);
    }
  } else {
    sendResponse(client_sock, error530);
  }
  return 0;
}

/**
  * Handle GETS-Get step data
  */
int fbGETS(char *params) {
  if (fb_state == LOGIN_SUCCESS) {
    if (params == NULL) {
      return sendResponse(client_sock, error520);
    }

    //This command expects only one argument
    //which is the username of the user whose steps are being collected
    khint_t k = getUser(params);

    if (k == kh_end(users)) {
      return sendResponse(client_sock, error400);
    } else {

      //Make sure the current user has a permission to
      //read step data of the given user
      if (strcmp(active_user_name, "admin") &&
          strcmp(active_user_name, params)) {
        if (!isFriend(params)) {
          return sendResponse(client_sock, error430);
        }
      }

      user_info_t *user = kh_value(users, k);

      if (user->step_count > 0) {
        sendResponse(client_sock, successcode);
        sendResponse(client_sock, " Steps: ");
        for (int i = 0; i < user->step_count; i++) {
          char tmpStepStr[MAX_NUMBER_LENGTH];
          sprintf(tmpStepStr, "%d", user->steps[i]);
          sendResponse(client_sock, tmpStepStr);
          if (i != user->step_count - 1) sendResponse(client_sock, ",");
        }
        sendResponse(client_sock, "\r\n");
      } else {
        sendResponse(client_sock, error420);
      }
    }
  } else {
    sendResponse(client_sock, error530);
  }
  return 0;
}

/**
  * Handle GETF-Get all friends of the current active user
  */
int fbGETF(char *params) {
  if (fb_state == LOGIN_SUCCESS) {
    //This command expects no arguments
    khint_t k = getUser(active_user_name);
    user_info_t *user = kh_value(users, k);

    if (user->friend_count > 0) {
      sendResponse(client_sock, successcode);
      sendResponse(client_sock, " Friends: ");
      for (int i = 0; i < user->friend_count; i++) {
        sendResponse(client_sock, user->friends[i]);
        if (i != user->friend_count - 1) sendResponse(client_sock, ",");
      }
      sendResponse(client_sock, "\r\n");
    } else {
      sendResponse(client_sock, error420);
    }
  } else {
    sendResponse(client_sock, error530);
  }
  return 0;
}

/**
  * Handle LOGO-Log out
  */
int fbLOGO(char *params) {
  if (fb_state == LOGIN_SUCCESS) {
    //This command expects no arguments
    sendResponse(client_sock, success260);
    fb_state = INIT;
  } else {
    sendResponse(client_sock, error530);
  }
  return 0;
}

/**
  * Handle QUIT-Terminate the server
  */
int fbQUIT(char *params) {
  //This command expects no arguments
  sendResponse(client_sock, success270);
  return 0;
}

/**
  * main function
  * It expects to take two arguments
  * arg_1: an IP address on which the server is running (e.g., 127.0.0.1)
  * arg_2: a port to which the server is listening (e.g., 8888)
  * arg_3: an IP address of the selected MFA service provider (e.g., 127.0.0.1)
  * arg_4: a port opened by the MFA service provider (e.g., 9999)
  * Example command: ./fotbot 127.0.0.1 8888 127.0.0.1 9999
  *
  */

int main(int argc , char *argv[]) {
  int fotbot_sock, addrlen, read_size;
  struct sockaddr_in server, client;
  char rcvbuf[CLIENT_REQUEST_MAX_SIZE];
  int exit_code = 0;

  //Initialize the "database"
  users = kh_init(hmu);

  //Check the number of arguments
  if (argc < 5) {
    fprintf(stderr, "[ERROR] FotBot requires four arguments: IPs and port numbers of FotBot and a MFA service provider\n");
    fprintf(stderr, "[ERROR] Sample command: ./fotbot 127.0.0.1 8888 127.0.0.1 9999\n");
    exit_code = 1;
    goto exit;
  }

  //Add a default admin user

  user_info_t *admin = newUser();
  admin->password = strdup("admin");
  admin->device_id = strdup("0123456789");

  ki = kh_put(hmu, users, "admin", &discard);
  kh_value(users, ki) = admin;

  /**
    * Set up the connection to the service provider (e.g., a telco)
    */
  struct sockaddr_in service_server;

  service_sock = socket(AF_INET , SOCK_STREAM , 0);
  if (service_sock == -1)
  {
    fprintf(stderr, "[ERROR] FotBot: cannot create a socket connecting to the service provider\n");
    exit_code = 1;
    goto exit;
  }

  //Enable reusing of local addresses
  const int trueFlag = 1;
  if (setsockopt(service_sock, SOL_SOCKET, SO_REUSEADDR, &trueFlag, sizeof(int)) < 0) {
    fprintf(stderr, "[ERROR] FotBot: cannot set a socket option for the service provider\n");
    exit_code = 1;
    goto exit;
  }

  service_server.sin_addr.s_addr = inet_addr(argv[3]);
  service_server.sin_family = AF_INET;
  service_server.sin_port = htons(atoi(argv[4]));

  //Connect to the service provider
  if (connect(service_sock, (struct sockaddr *)&service_server, sizeof(service_server)) < 0)
  {
    fprintf(stderr, "[ERROR] FotBot: cannot connect to the service provider server\n");
    exit_code = 1;
    goto exit;
  } else {
    fprintf(stdout, "FotBot: successfully connect to the service provider\n");
  }

  /**
    * Create a TCP socket for FotBot to accept client requests
    */
  fotbot_sock = socket(AF_INET , SOCK_STREAM , 0);
  if (fotbot_sock == -1) {
    fprintf(stderr, "[ERROR] FotBot: cannot create a socket\n");
    exit_code = 1;
    goto exit;
  }

  //Enable reusing of local addresses
  if (setsockopt(fotbot_sock, SOL_SOCKET, SO_REUSEADDR, &trueFlag, sizeof(int)) < 0) {
    fprintf(stderr, "[ERROR] FotBot: cannot set a socket option for the server\n");
    exit_code = 1;
    goto exit;
  }

  //Prepare a sockaddr_in structure for the server
  server.sin_family = AF_INET;
  server.sin_addr.s_addr = inet_addr(argv[1]);
  server.sin_port = htons(atoi(argv[2]));

  //Bind a socket to the server
  if(bind(fotbot_sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
    fprintf(stderr, "[ERROR] FotBot: bind failed. error code is %d\n", errno);
    exit_code = 1;
    goto exit;
  }

  //Listen to incoming connection request
  fprintf(stdout, "FotBot: waiting for an incoming connection ...\n");

  //For simplicity, this server accepts only one connection
  listen(fotbot_sock, 1);
  addrlen = sizeof(struct sockaddr_in);

  client_sock = accept(fotbot_sock, (struct sockaddr *)&client, (socklen_t*)&addrlen);
  if (client_sock < 0) {
    fprintf(stderr, "[ERROR] FotBot fails to accept an incoming connection\n");
    exit_code = 1;
    goto exit;
  }

  fprintf(stdout, "FotBot: connection accepted\n");

  int i, j, cmdlen, cmdno, rv;
  char *cmd = NULL, *params = NULL;
  //Receive requests from client
  while (fotbot_sock != INVALID_SOCKET) {
    read_size = recvcmd(client_sock, rcvbuf, CLIENT_REQUEST_MAX_SIZE);
    if (read_size <= 0) break;
    fprintf(stdout,"FotBot: receiving %s\n", rcvbuf);

    //Identify the command
    i = 0;
    while ((rcvbuf[i] != 0) && (isalpha(rcvbuf[i]) == 0)) ++i;

    cmd = &rcvbuf[i];
    while ((rcvbuf[i] != 0) && (rcvbuf[i] != ' ')) ++i;

    //Skip space characters between command & parameters
    cmdlen = &rcvbuf[i] - cmd;
    while (rcvbuf[i] == ' ') ++i;

    //Get parameters
    if (rcvbuf[i] == 0) params = NULL;
    else params = &rcvbuf[i];

    cmdno = -1; //command number
    rv = 1;     //value returned from the command handling function

    for (j = 0; j < MAX_CMDS; j++) {
      if (strncasecmp(cmd, fbprocs[j].name, cmdlen) == 0) {
        //The given command is supported
        cmdno = j;
        rv = fbprocs[j].proc(params); //call corresponding command-handling function
        break;
      }
    }

    //The given command is *not* supported
    if (cmdno == -1) {
      sendResponse(client_sock, error500);
    }

    if (cmdno == CMD_QUIT) {
      goto exit;
    }
  }

  if(read_size == 0) {
    fprintf(stdout, "FotBot: client disconnected\n");
  } else if(read_size == -1) {
    fprintf(stderr, "[ERROR] FotBot fails to receive client requests\n");
    exit_code = 1;
    goto exit;
  }

exit:
  //free up memory
  freeUsers();
  return exit_code;
}
