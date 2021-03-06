///
/// ObjC.h
///
/// @author Florian Draschbacher
/// @copyright © 2018 Florian Draschbacher. All rights reserved.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
/// http://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#import "ObjC.h"

@implementation ObjC

+ (BOOL)catchException:(void(^)())tryBlock error:(__autoreleasing NSError **)error {
  @try {
    tryBlock();
    return YES;
  }
  @catch (NSException *exception) {
    NSMutableDictionary *userInfo = [[NSMutableDictionary alloc] initWithDictionary:exception.userInfo];
    [userInfo setObject:exception forKey:@"exception"];
    *error = [[NSError alloc] initWithDomain:exception.name code:0 userInfo:userInfo];
    return NO;
  }
}

+ (void)throwException:(id)exception{
  @throw exception;
}

@end
