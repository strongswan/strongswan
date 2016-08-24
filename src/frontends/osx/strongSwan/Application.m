/*
 * Copyright (C) 2016 Martin Willi
 * Copyright (C) 2016 revosec AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#import "Application.h"

@implementation Application

- (void) sendEvent:(NSEvent *)event {

	if ([event type] == NSKeyDown) {

		if (([event modifierFlags] &
			 NSDeviceIndependentModifierFlagsMask) == NSCommandKeyMask) {

			if ([[event charactersIgnoringModifiers] isEqualToString:@"x"]) {
				if ([self sendAction:@selector(cut:) to:nil from:self])
					return;
			}
			else if ([[event charactersIgnoringModifiers] isEqualToString:@"c"]) {
				if ([self sendAction:@selector(copy:) to:nil from:self])
					return;
			}
			else if ([[event charactersIgnoringModifiers] isEqualToString:@"v"]) {
				if ([self sendAction:@selector(paste:) to:nil from:self])
					return;
			}
			else if ([[event charactersIgnoringModifiers] isEqualToString:@"a"]) {
				if ([self sendAction:@selector(selectAll:) to:nil from:self])
					return;
			}
		}
	}

	[super sendEvent:event];
}

@end
