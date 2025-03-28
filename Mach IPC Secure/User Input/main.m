//
//  main.m
//  Mach IPC Client
//
//  Created by Kamalakannan N G on 25/03/25.
//

#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <servers/bootstrap.h>

#define MACH_PORT_NAME "com.example.MachIPCServer"

@interface Client : NSObject
- (void)sendCommand:(NSString *)command withMessage:(NSString *)message;
@end

@implementation Client {
    mach_port_t serverPort;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        kern_return_t kr = bootstrap_look_up(bootstrap_port, MACH_PORT_NAME, &serverPort);
        if (kr != KERN_SUCCESS) {
            NSLog(@"Client: Failed to look up server port!");
            return nil;
        }
        NSLog(@"Client: Found server port: %u", serverPort);
    }
    return self;
}

- (void)sendCommand:(NSString *)command withMessage:(NSString *)message {
    mach_port_t replyPort;

    kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &replyPort);
    if (kr != KERN_SUCCESS) {
        NSLog(@"Client: Failed to allocate reply port!");
        return;
    }

    kr = mach_port_insert_right(mach_task_self(), replyPort, replyPort, MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS) {
        NSLog(@"Client: Failed to insert send right to reply port!");
        return;
    }

    struct {
        mach_msg_header_t header;
        mach_msg_body_t body;
        mach_msg_port_descriptor_t replyPortDescriptor;
        char messageBody[1024];
    } msg;

    memset(&msg, 0, sizeof(msg));

    msg.header.msgh_bits = MACH_MSGH_BITS_REMOTE(MACH_MSG_TYPE_COPY_SEND) | MACH_MSGH_BITS_COMPLEX;
    msg.header.msgh_size = sizeof(msg);
    msg.header.msgh_remote_port = serverPort;
    msg.header.msgh_local_port = MACH_PORT_NULL;
    msg.header.msgh_id = 100;

    msg.body.msgh_descriptor_count = 1;
    msg.replyPortDescriptor.name = replyPort;
    msg.replyPortDescriptor.disposition = MACH_MSG_TYPE_MAKE_SEND;
    msg.replyPortDescriptor.type = MACH_MSG_PORT_DESCRIPTOR;

    snprintf(msg.messageBody, sizeof(msg.messageBody), "%s%s%s",
             [command UTF8String],
             message.length > 0 ? ":" : "",
             [message UTF8String]);

    kr = mach_msg_send((mach_msg_header_t *)&msg);
    if (kr != KERN_SUCCESS) {
        NSLog(@"Client: Failed to send command! Error code: %d", kr);
        return;
    }

    NSLog(@"Client: Sent command: %@ %@", command, message);


    struct {
        mach_msg_header_t header;
        char responseBody[1024 * 2048];
    } response;

    memset(&response, 0, sizeof(response));

    kr = mach_msg(&response.header,
                  MACH_RCV_MSG,
                  0,
                  sizeof(response),
                  replyPort,
                  2000,
                  MACH_PORT_NULL);

    if (kr != KERN_SUCCESS) {
        NSLog(@"Client: No response received within timeout! Error: %d (%s)", kr, mach_error_string(kr));
        mach_port_deallocate(mach_task_self(), replyPort);
        return;
    }

    NSString *responseStr = [NSString stringWithUTF8String:response.responseBody];
    NSLog(@"Client: Received response from server: %@", responseStr);

    mach_port_deallocate(mach_task_self(), replyPort);

}

@end

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        Client *client = [[Client alloc] init];
        if (!client) {
            return -1;
        }

        char input[1024];
        while (true) {
            NSLog(@"Enter command (READ / WRITE <message> / EXIT): ");
            fgets(input, sizeof(input), stdin);

            NSString *inputStr = [[NSString stringWithUTF8String:input] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
            NSArray *components = [inputStr componentsSeparatedByString:@" "];

            if (components.count == 0) {
                continue;
            }

            NSString *command = components[0];
            NSString *message = components.count > 1 ? components[1] : @"";
            if ([command isEqualToString:@"EXIT"]) {
                break;
            }

            [client sendCommand:command withMessage:message];

        }
    }
    return 0;
}
