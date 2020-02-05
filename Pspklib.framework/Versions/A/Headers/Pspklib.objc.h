// Objective-C API for talking to github.com/l-vitaly/pspklib Go package.
//   gobind -lang=objc github.com/l-vitaly/pspklib
//
// File is generated by gobind. Do not edit.

#ifndef __Pspklib_H__
#define __Pspklib_H__

@import Foundation;
#include "ref.h"
#include "Universe.objc.h"

#include "Pspk.objc.h"

@class PspklibAPI;
@class PspklibGenerateDHResult;
@class PspklibGetAllOptions;
@class PspklibKeys;
@class PspklibPspk;
@protocol PspklibKey;
@class PspklibKey;

@protocol PspklibKey <NSObject>
- (NSString* _Nonnull)id_;
- (NSString* _Nonnull)key;
- (NSString* _Nonnull)name;
@end

@interface PspklibAPI : NSObject <goSeqRefInterface> {
}
@property(strong, readonly) _Nonnull id _ref;

- (nonnull instancetype)initWithRef:(_Nonnull id)ref;
- (nullable instancetype)init:(NSString* _Nullable)basePath;
- (NSString* _Nonnull)downloadByLink:(NSString* _Nullable)link error:(NSError* _Nullable* _Nullable)error;
- (NSString* _Nonnull)generateLink:(NSString* _Nullable)data error:(NSError* _Nullable* _Nullable)error;
- (PspklibKeys* _Nullable)getAll:(PspklibGetAllOptions* _Nullable)opts error:(NSError* _Nullable* _Nullable)error;
- (NSData* _Nullable)load:(NSString* _Nullable)name error:(NSError* _Nullable* _Nullable)error;
- (BOOL)publish:(NSString* _Nullable)name key:(NSData* _Nullable)key error:(NSError* _Nullable* _Nullable)error;
@end

@interface PspklibGenerateDHResult : NSObject <goSeqRefInterface> {
}
@property(strong, readonly) _Nonnull id _ref;

- (nonnull instancetype)initWithRef:(_Nonnull id)ref;
- (nonnull instancetype)init;
@property (nonatomic) NSData* _Nullable priv;
@property (nonatomic) NSData* _Nullable pub;
@end

@interface PspklibGetAllOptions : NSObject <goSeqRefInterface> {
}
@property(strong, readonly) _Nonnull id _ref;

- (nonnull instancetype)initWithRef:(_Nonnull id)ref;
- (nonnull instancetype)init;
@property (nonatomic) NSString* _Nonnull nameKey;
@property (nonatomic) NSString* _Nonnull nameRegex;
@property (nonatomic) NSString* _Nonnull output;
@property (nonatomic) NSString* _Nonnull lastKey;
@property (nonatomic) long limit;
@end

@interface PspklibKeys : NSObject <goSeqRefInterface> {
}
@property(strong, readonly) _Nonnull id _ref;

- (nonnull instancetype)initWithRef:(_Nonnull id)ref;
- (nonnull instancetype)init;
- (id<PspklibKey> _Nullable)at:(long)i;
- (long)len;
- (NSData* _Nullable)marshalJSON:(NSError* _Nullable* _Nullable)error;
- (BOOL)unmarshalJSON:(NSData* _Nullable)b error:(NSError* _Nullable* _Nullable)error;
@end

@interface PspklibPspk : NSObject <goSeqRefInterface> {
}
@property(strong, readonly) _Nonnull id _ref;

- (nonnull instancetype)initWithRef:(_Nonnull id)ref;
/**
 * NewPspk makes a new Pspk.
 */
- (nullable instancetype)init;
- (NSData* _Nullable)decrypt:(NSData* _Nullable)key cipherText:(NSData* _Nullable)cipherText error:(NSError* _Nullable* _Nullable)error;
- (NSData* _Nullable)encrypt:(NSData* _Nullable)key plaintext:(NSData* _Nullable)plaintext error:(NSError* _Nullable* _Nullable)error;
- (PspklibGenerateDHResult* _Nullable)generateDH:(NSError* _Nullable* _Nullable)error;
- (NSData* _Nullable)hkdf:(NSData* _Nullable)secret outputLen:(long)outputLen error:(NSError* _Nullable* _Nullable)error;
- (NSData* _Nullable)loadMaterialKey:(NSData* _Nullable)chain error:(NSError* _Nullable* _Nullable)error;
- (NSData* _Nullable)secret:(NSData* _Nullable)priv pub:(NSData* _Nullable)pub error:(NSError* _Nullable* _Nullable)error;
- (NSData* _Nullable)secretLatestKey;
- (NSData* _Nullable)sign:(NSData* _Nullable)priv message:(NSData* _Nullable)message random:(NSData* _Nullable)random error:(NSError* _Nullable* _Nullable)error;
@end

FOUNDATION_EXPORT PspklibAPI* _Nullable PspklibNewAPI(NSString* _Nullable basePath);

/**
 * NewPspk makes a new Pspk.
 */
FOUNDATION_EXPORT PspklibPspk* _Nullable PspklibNewPspk(void);

@class PspklibKey;

@interface PspklibKey : NSObject <goSeqRefInterface, PspklibKey> {
}
@property(strong, readonly) _Nonnull id _ref;

- (nonnull instancetype)initWithRef:(_Nonnull id)ref;
- (NSString* _Nonnull)id_;
- (NSString* _Nonnull)key;
- (NSString* _Nonnull)name;
@end

#endif