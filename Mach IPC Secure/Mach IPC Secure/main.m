//
//  main.m
//  Mach IPC Secure
//
//  Created by Kamala Kannan N G on 25/03/25.
//

#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <servers/bootstrap.h>
#import <security/Security.h>
#import <bsm/libbsm.h>

extern int csops(pid_t pid, int ops, void *useraddr, size_t usersize);
#define CS_OPS_TEAMID 6

#define MACH_PORT_NAME "com.example.MachIPCServer"

typedef struct {
    mach_msg_header_t header;
    mach_msg_body_t body;
    mach_msg_port_descriptor_t clientPort;
    char message[1024 * 1024];
} MachMessage;

typedef struct {
    mach_msg_header_t header;
    char responseBody[1024];
} MachReplyMessage;

@interface Server : NSObject
@property (nonatomic, strong) NSString *plistPath;
- (void)startServer;
@end

@implementation Server {
    mach_port_t serverPort;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        NSString *dirPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Library/Application Support/MySecureApp"];
        [[NSFileManager defaultManager] createDirectoryAtPath:dirPath withIntermediateDirectories:YES attributes:nil error:nil];
        _plistPath = [dirPath stringByAppendingPathComponent:@"data.plist"];
        
        if (![[NSFileManager defaultManager] fileExistsAtPath:_plistPath]) {
            [self writePlist:@"Default message"];
        }
    }
    return self;
}

- (void)startServer {
    kern_return_t kr;
    mach_port_t bootstrap;
    
    task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &bootstrap);

    kr = bootstrap_check_in(bootstrap, MACH_PORT_NAME, &serverPort);
    if (kr != KERN_SUCCESS) {
        NSLog(@"ERROR: Failed to check in Mach port with launchd! Ensure your process is started via launchctl.");
        return;
    }

    NSLog(@"[Server] Started! Listening on port: %d", serverPort);
    [self listenForCommands];
}

- (NSString *)getTeamIDForPID:(pid_t)pid {
    char teamID[1024] = {0};
    int csopsResult = csops(pid, CS_OPS_TEAMID, teamID, sizeof(teamID));

    if (csopsResult == -1) {
        NSLog(@"[Server] csops() failed for PID %d with errno %d (%s)", pid, errno, strerror(errno));
        return nil;
    }

    return [NSString stringWithUTF8String:teamID];
}

- (BOOL)isClientAuthorized:(pid_t)clientPID {
    NSString *clientTeamID = [self getTeamIDForPID:clientPID];
    NSString *serverTeamID = [self getTeamIDForPID:getpid()];

    if (!clientTeamID || !serverTeamID) {
        NSLog(@"[Server] Client verification failed! Client Team ID: %@, Server Team ID: %@", clientTeamID, serverTeamID);
        return NO;
    }

    if (![clientTeamID isEqualToString:serverTeamID]) {
        NSLog(@"[Server] Unauthorized client! Client Team ID: %@, Server Team ID: %@", clientTeamID, serverTeamID);
        return NO;
    }

    NSLog(@"[Server] Client verified successfully! Team ID: %@", clientTeamID);
    return YES;
}

- (void)listenForCommands {
    while (true) {
        NSLog(@"[Server] Listening for command...");
        
        MachMessage msg;
        kern_return_t kr = mach_msg(&msg.header,
                                    MACH_RCV_MSG | MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) | MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT),
                                    0,
                                    sizeof(MachMessage),
                                    serverPort,
                                    MACH_MSG_TIMEOUT_NONE,
                                    MACH_PORT_NULL);

        if (kr != KERN_SUCCESS) {
            NSLog(@"[Server] Error receiving command! Code: %d (%s)", kr, mach_error_string(kr));
            continue;
        }

        mach_msg_audit_trailer_t *trailer = (mach_msg_audit_trailer_t *)((uint8_t *)&msg + msg.header.msgh_size);

        if (trailer->msgh_trailer_size < sizeof(mach_msg_audit_trailer_t)) {
            NSLog(@"[Server] Error: Invalid trailer size! Expected: %lu, Got: %d",
                  sizeof(mach_msg_audit_trailer_t), trailer->msgh_trailer_size);
            continue;
        }

        pid_t clientPID = trailer->msgh_audit.val[5];
        NSLog(@"[Server] Received PID from client: %d", clientPID);

        if (![self isClientAuthorized:clientPID]) {
            NSLog(@"[Server] Unauthorized client! Rejecting request.");
            continue;
        }

        mach_port_t clientReplyPort = msg.clientPort.name;
        if (clientReplyPort == MACH_PORT_NULL) {
            NSLog(@"[Server] Error: Client reply port is null!");
            continue;
        }

        NSString *receivedMessage = [NSString stringWithUTF8String:msg.message];
        receivedMessage = [receivedMessage stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];

        NSArray<NSString *> *components = [receivedMessage componentsSeparatedByString:@":"];
        NSString *command = components.firstObject;
        NSString *message = (components.count > 1) ? components[1] : @"";

        NSLog(@"[Server] Received Command: %@ | Message: %@", command, message);

        NSString *response;
        if ([command isEqualToString:@"READ"]) {
            response = [self readPlist];
        } else if ([command isEqualToString:@"WRITE"]) {
            if (message.length == 0) {
                response = @"WRITE command requires a message!";
            } else {
                [self writePlist:message];
                response = @"Write Successful";
            }
        } else {
            response = @"Invalid Command";
        }
        
        NSLog(@"[Server] Sending Response: %@", response);

        MachReplyMessage replyMsg;
        memset(&replyMsg, 0, sizeof(replyMsg));

        replyMsg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
        replyMsg.header.msgh_size = sizeof(replyMsg);
        replyMsg.header.msgh_remote_port = clientReplyPort;
        replyMsg.header.msgh_local_port = MACH_PORT_NULL;
        replyMsg.header.msgh_id = 200;

        snprintf(replyMsg.responseBody, sizeof(replyMsg.responseBody), "%s", [response UTF8String]);

        kr = mach_msg_send((mach_msg_header_t *)&replyMsg);
        if (kr != KERN_SUCCESS) {
            NSLog(@"[Server] Failed to send response! Error: %s", mach_error_string(kr));
        } else {
            NSLog(@"[Server] Response Sent!");
        }
    }
}

- (NSString *)readPlist {
    NSDictionary *data = [NSDictionary dictionaryWithContentsOfFile:self.plistPath];
    return data[@"message"] ?: @"Error: Cannot read plist!";
}

- (void)writePlist:(NSString *)message {
    NSDictionary *data = @{@"message": message};
    [data writeToFile:self.plistPath atomically:YES];
    NSLog(@"[Server] Written to plist: %@", message);
}

@end

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        Server *server = [[Server alloc] init];
        [server startServer];
    }
    return 0;
}
