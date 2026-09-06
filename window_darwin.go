//go:build darwin && cgo

package main

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Cocoa -framework WebKit
#import <Cocoa/Cocoa.h>
#import <WebKit/WebKit.h>

@interface GofingMenuActionTarget : NSObject
+ (instancetype)shared;
- (void)openDocumentation:(id)sender;
@end

@implementation GofingMenuActionTarget
+ (instancetype)shared {
    static GofingMenuActionTarget *inst = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        inst = [[GofingMenuActionTarget alloc] init];
    });
    return inst;
}
- (void)openDocumentation:(id)sender {
    [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:@"https://github.com/jaredwarren/Gofing"]];
}
@end

static void build_native_main_menu(NSString *appName) {
    NSApplication *app = [NSApplication sharedApplication];
    NSMenu *mainMenu = [[NSMenu alloc] init];

    // 1. Application Menu (Gofing)
    NSMenuItem *appMenuItem = [[NSMenuItem alloc] init];
    NSMenu *appMenu = [[NSMenu alloc] initWithTitle:appName];

    [appMenu addItemWithTitle:[NSString stringWithFormat:@"About %@", appName]
                       action:@selector(orderFrontStandardAboutPanel:)
                keyEquivalent:@""];
    [appMenu addItem:[NSMenuItem separatorItem]];

    NSMenuItem *hideItem = [appMenu addItemWithTitle:[NSString stringWithFormat:@"Hide %@", appName]
                                              action:@selector(hide:)
                                       keyEquivalent:@"h"];
    [hideItem setKeyEquivalentModifierMask:NSEventModifierFlagCommand];

    NSMenuItem *hideOthersItem = [appMenu addItemWithTitle:@"Hide Others"
                                                    action:@selector(hideOtherApplications:)
                                             keyEquivalent:@"h"];
    [hideOthersItem setKeyEquivalentModifierMask:(NSEventModifierFlagOption | NSEventModifierFlagCommand)];

    [appMenu addItemWithTitle:@"Show All"
                       action:@selector(unhideAllApplications:)
                keyEquivalent:@""];
    [appMenu addItem:[NSMenuItem separatorItem]];

    NSMenuItem *quitItem = [appMenu addItemWithTitle:[NSString stringWithFormat:@"Quit %@", appName]
                                              action:@selector(terminate:)
                                       keyEquivalent:@"q"];
    [quitItem setKeyEquivalentModifierMask:NSEventModifierFlagCommand];

    [appMenuItem setSubmenu:appMenu];
    [mainMenu addItem:appMenuItem];

    // 2. File Menu
    NSMenuItem *fileMenuItem = [[NSMenuItem alloc] init];
    NSMenu *fileMenu = [[NSMenu alloc] initWithTitle:@"File"];
    [fileMenu addItemWithTitle:@"Close Window" action:@selector(performClose:) keyEquivalent:@"w"];
    [fileMenuItem setSubmenu:fileMenu];
    [mainMenu addItem:fileMenuItem];

    // 3. Edit Menu (crucial for Cmd+C, Cmd+V, Cmd+A in search/inputs)
    NSMenuItem *editMenuItem = [[NSMenuItem alloc] init];
    NSMenu *editMenu = [[NSMenu alloc] initWithTitle:@"Edit"];
    [editMenu addItemWithTitle:@"Undo" action:@selector(undo:) keyEquivalent:@"z"];
    NSMenuItem *redo = [editMenu addItemWithTitle:@"Redo" action:@selector(redo:) keyEquivalent:@"Z"];
    [redo setKeyEquivalentModifierMask:(NSEventModifierFlagShift | NSEventModifierFlagCommand)];
    [editMenu addItem:[NSMenuItem separatorItem]];
    [editMenu addItemWithTitle:@"Cut" action:@selector(cut:) keyEquivalent:@"x"];
    [editMenu addItemWithTitle:@"Copy" action:@selector(copy:) keyEquivalent:@"c"];
    [editMenu addItemWithTitle:@"Paste" action:@selector(paste:) keyEquivalent:@"v"];
    [editMenu addItemWithTitle:@"Select All" action:@selector(selectAll:) keyEquivalent:@"a"];
    [editMenuItem setSubmenu:editMenu];
    [mainMenu addItem:editMenuItem];

    // 4. View Menu
    NSMenuItem *viewMenuItem = [[NSMenuItem alloc] init];
    NSMenu *viewMenu = [[NSMenu alloc] initWithTitle:@"View"];
    NSMenuItem *fullScreen = [viewMenu addItemWithTitle:@"Toggle Full Screen"
                                                 action:@selector(toggleFullScreen:)
                                          keyEquivalent:@"f"];
    [fullScreen setKeyEquivalentModifierMask:(NSEventModifierFlagControl | NSEventModifierFlagCommand)];
    [viewMenuItem setSubmenu:viewMenu];
    [mainMenu addItem:viewMenuItem];

    // 5. Window Menu
    NSMenuItem *windowMenuItem = [[NSMenuItem alloc] init];
    NSMenu *windowMenu = [[NSMenu alloc] initWithTitle:@"Window"];
    [windowMenu addItemWithTitle:@"Minimize" action:@selector(performMiniaturize:) keyEquivalent:@"m"];
    [windowMenu addItemWithTitle:@"Zoom" action:@selector(performZoom:) keyEquivalent:@""];
    [windowMenu addItem:[NSMenuItem separatorItem]];
    [windowMenu addItemWithTitle:@"Bring All to Front" action:@selector(arrangeInFront:) keyEquivalent:@""];
    [windowMenuItem setSubmenu:windowMenu];
    [mainMenu addItem:windowMenuItem];

    // 6. Help Menu
    NSMenuItem *helpMenuItem = [[NSMenuItem alloc] init];
    NSMenu *helpMenu = [[NSMenu alloc] initWithTitle:@"Help"];
    NSMenuItem *helpDoc = [helpMenu addItemWithTitle:@"Documentation & Source"
                                              action:@selector(openDocumentation:)
                                       keyEquivalent:@"?"];
    [helpDoc setTarget:[GofingMenuActionTarget shared]];
    [helpMenuItem setSubmenu:helpMenu];
    [mainMenu addItem:helpMenuItem];

    [app setMainMenu:mainMenu];
    [app setWindowsMenu:windowMenu];
    [app setHelpMenu:helpMenu];
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

@interface GofingNativeAppDelegate : NSObject <NSApplicationDelegate, NSWindowDelegate, WKNavigationDelegate, NSUserNotificationCenterDelegate>
@property (strong) NSWindow *window;
@property (strong) WKWebView *webView;
@property (copy) NSString *targetURL;
@end

@implementation GofingNativeAppDelegate

- (instancetype)initWithURL:(NSString *)url {
    self = [super init];
    if (self) {
        _targetURL = [url copy];
    }
    return self;
}

- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    // Ensure notifications are delivered and displayed as alert banners even when Gofing is the frontmost active window
    [NSUserNotificationCenter defaultUserNotificationCenter].delegate = self;

    // 1. Build and install top macOS menu bar
    build_native_main_menu(@"Gofing");

    // 2. Create standard native macOS window
    NSRect frame = NSMakeRect(0, 0, 1280, 860);
    NSUInteger style = NSWindowStyleMaskTitled |
                       NSWindowStyleMaskClosable |
                       NSWindowStyleMaskMiniaturizable |
                       NSWindowStyleMaskResizable;
    self.window = [[NSWindow alloc] initWithContentRect:frame
                                              styleMask:style
                                                backing:NSBackingStoreBuffered
                                                  defer:NO];
    [self.window setTitle:@"Gofing"];
    [self.window center];
    [self.window setMinSize:NSMakeSize(800, 500)];
    self.window.delegate = self;

    // 3. Configure native WKWebView
    WKWebViewConfiguration *config = [[WKWebViewConfiguration alloc] init];
    self.webView = [[WKWebView alloc] initWithFrame:[self.window.contentView bounds]
                                      configuration:config];
    self.webView.navigationDelegate = self;
    [self.webView setAutoresizingMask:(NSViewWidthSizable | NSViewHeightSizable)];
    [self.window.contentView addSubview:self.webView];

    // 4. Load localhost service URL
    if (self.targetURL && self.targetURL.length > 0) {
        NSURL *url = [NSURL URLWithString:self.targetURL];
        NSURLRequest *request = [NSURLRequest requestWithURL:url];
        [self.webView loadRequest:request];
    }

    [self.window makeKeyAndOrderFront:nil];
    [NSApp activateIgnoringOtherApps:YES];
}

// Force macOS to always present notification banners even when the window is frontmost
- (BOOL)userNotificationCenter:(NSUserNotificationCenter *)center shouldPresentNotification:(NSUserNotification *)notification {
    return YES;
}

- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)sender {
    return YES;
}

- (void)windowWillClose:(NSNotification *)notification {
    [NSApp terminate:nil];
}

- (BOOL)applicationShouldHandleReopen:(NSApplication *)sender hasVisibleWindows:(BOOL)flag {
    if (!flag && self.window) {
        [self.window makeKeyAndOrderFront:nil];
    }
    return YES;
}

// Open external links in default browser (e.g. GitHub documentation)
- (void)webView:(WKWebView *)webView decidePolicyForNavigationAction:(WKNavigationAction *)navigationAction decisionHandler:(void (^)(WKNavigationActionPolicy))decisionHandler {
    NSURL *url = navigationAction.request.URL;
    if (url && (url.scheme != nil) && ([url.scheme isEqualToString:@"http"] || [url.scheme isEqualToString:@"https"])) {
        NSString *host = url.host;
        // Keep localhost / 127.0.0.1 in the app
        if ([host isEqualToString:@"127.0.0.1"] || [host isEqualToString:@"localhost"]) {
            decisionHandler(WKNavigationActionPolicyAllow);
            return;
        }
        // External URLs open in the system default web browser
        [[NSWorkspace sharedWorkspace] openURL:url];
        decisionHandler(WKNavigationActionPolicyCancel);
        return;
    }
    decisionHandler(WKNavigationActionPolicyAllow);
}

@end

static void run_cocoa_window(const char *urlStr) {
    @autoreleasepool {
        NSApplication *app = [NSApplication sharedApplication];
        [app setActivationPolicy:NSApplicationActivationPolicyRegular];
        NSString *url = [NSString stringWithUTF8String:urlStr];
        GofingNativeAppDelegate *delegate = [[GofingNativeAppDelegate alloc] initWithURL:url];
        [app setDelegate:delegate];
        [app run];
    }
}

static void terminate_cocoa_app(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        [NSApp terminate:nil];
    });
}

#pragma clang diagnostic pop
*/
import "C"
import (
	"runtime"
	"unsafe"
)

func init() {
	// macOS AppKit and WKWebView require main runloop on OS thread 0
	runtime.LockOSThread()
}

func runNativeWindow(targetURL string) {
	cURL := C.CString(targetURL)
	defer C.free(unsafe.Pointer(cURL))
	C.run_cocoa_window(cURL)
}

func terminateNativeApp() {
	C.terminate_cocoa_app()
}
