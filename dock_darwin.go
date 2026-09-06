//go:build darwin && cgo

package main

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Cocoa
#import <Cocoa/Cocoa.h>

static void set_macos_dock_icon(const void* data, int len) {
    @autoreleasepool {
        NSData* nsData = [NSData dataWithBytes:data length:len];
        NSImage* img = [[NSImage alloc] initWithData:nsData];
        if (img) {
            NSApplication* app = [NSApplication sharedApplication];
            [app setApplicationIconImage:img];
        }
    }
}
*/
import "C"
import "unsafe"

func setNativeDockIcon(pngBytes []byte) {
	if len(pngBytes) == 0 {
		return
	}
	C.set_macos_dock_icon(unsafe.Pointer(&pngBytes[0]), C.int(len(pngBytes)))
}

