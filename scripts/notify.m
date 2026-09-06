#import <Cocoa/Cocoa.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

@interface NotificationDelegate : NSObject <NSUserNotificationCenterDelegate>
@property (assign) BOOL delivered;
@end

@implementation NotificationDelegate
- (BOOL)userNotificationCenter:(NSUserNotificationCenter *)center shouldPresentNotification:(NSUserNotification *)notification {
    return YES;
}
- (void)userNotificationCenter:(NSUserNotificationCenter *)center didDeliverNotification:(NSUserNotification *)notification {
    self.delivered = YES;
}
@end

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        if (argc < 3) return 1;
        NSString *title = [NSString stringWithUTF8String:argv[1]];
        NSString *msg = [NSString stringWithUTF8String:argv[2]];

        NSUserNotification *notif = [[NSUserNotification alloc] init];
        notif.title = title;
        notif.informativeText = msg;
        notif.soundName = NSUserNotificationDefaultSoundName;

        if (argc >= 4) {
            NSString *iconPath = [NSString stringWithUTF8String:argv[3]];
            NSImage *img = [[NSImage alloc] initWithContentsOfFile:iconPath];
            if (img) {
                notif.contentImage = img;
                @try {
                    [notif setValue:img forKey:@"_identityImage"];
                    [notif setValue:@(NO) forKey:@"_identityImageHasBorder"];
                } @catch (NSException *e) {}
            }
        }

        NotificationDelegate *delegate = [[NotificationDelegate alloc] init];
        NSUserNotificationCenter *center = [NSUserNotificationCenter defaultUserNotificationCenter];
        center.delegate = delegate;
        [center deliverNotification:notif];

        NSDate *limit = [NSDate dateWithTimeIntervalSinceNow:0.5];
        while (!delegate.delivered && [limit timeIntervalSinceNow] > 0) {
            [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.05]];
        }
    }
    return 0;
}
#pragma clang diagnostic pop


