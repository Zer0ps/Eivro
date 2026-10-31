#import "eivro.h"
#import <AppKit/AppKit.h>
#import <Security/Authorization.h>
#import <Security/AuthorizationTags.h>
#import <SystemConfiguration/SCDynamicStoreCopyDHCPInfo.h>
#import <SystemConfiguration/SystemConfiguration.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <string.h>

static char *jsonCopy(id value) {
    if (!value)
        return NULL;
    NSData *data = [NSJSONSerialization dataWithJSONObject:value
                                                   options:NSJSONWritingFragmentsAllowed
                                                     error:NULL];
    if (!data || data.length > 4 * 1024 * 1024)
        return NULL;
    char *result = malloc(data.length + 1);
    if (result) {
        memcpy(result, data.bytes, data.length);
        result[data.length] = 0;
    }
    return result;
}
static NSDictionary *state(SCDynamicStoreRef store, NSString *key) {
    id value = CFBridgingRelease(SCDynamicStoreCopyValue(store, (__bridge CFStringRef)key));
    return [value isKindOfClass:[NSDictionary class]] ? value : @{};
}
static NSDictionary *primary(SCDynamicStoreRef store) {
    NSDictionary *v4 = state(store, @"State:/Network/Global/IPv4");
    return [v4[@"PrimaryInterface"] isKindOfClass:[NSString class]]
               ? v4
               : state(store, @"State:/Network/Global/IPv6");
}
char *eivro_uplink(void) {
    @autoreleasepool {
        SCDynamicStoreRef store = SCDynamicStoreCreate(NULL, CFSTR("Eivro uplink"), NULL, NULL);
        if (!store)
            return NULL;
        NSString *name = primary(store)[@"PrimaryInterface"];
        char *result = [name isKindOfClass:[NSString class]] && ![name hasPrefix:@"utun"] &&
                               ![name isEqualToString:@"lo0"]
                           ? jsonCopy(name)
                           : NULL;
        CFRelease(store);
        return result;
    }
}
char *eivro_interfaces(void) {
    @autoreleasepool {
        struct ifaddrs *list = NULL;
        if (getifaddrs(&list) != 0)
            return NULL;
        NSMutableDictionary *links = [NSMutableDictionary dictionary];
        for (struct ifaddrs *item = list; item; item = item->ifa_next) {
            NSString *name = [NSString stringWithUTF8String:item->ifa_name];
            if (!name || (item->ifa_flags & IFF_LOOPBACK) || [name isEqualToString:@"utun233"])
                continue;
            if (!links[name])
                links[name] = [@{
                    @"name" : name,
                    @"index" : @(if_nametoindex(item->ifa_name)),
                    @"up" : @((bool)((item->ifa_flags & IFF_UP) != 0)),
                    @"dns" : [NSMutableArray array]
                } mutableCopy];
        }
        freeifaddrs(list);
        SCDynamicStoreRef store = SCDynamicStoreCreate(NULL, CFSTR("Eivro interfaces"), NULL, NULL);
        if (!store)
            return NULL;
        NSArray *keys = CFBridgingRelease(
            SCDynamicStoreCopyKeyList(store, CFSTR("State:/Network/Service/.*/DNS")));
        for (NSString *key in keys) {
            NSString *prefix = [key substringToIndex:key.length - 3];
            NSString *name =
                state(store, [prefix stringByAppendingString:@"IPv4"])[@"InterfaceName"];
            if (!name)
                name = state(store, [prefix stringByAppendingString:@"IPv6"])[@"InterfaceName"];
            NSMutableArray *dns = links[name ? name : @""][@"dns"];
            if (!dns)
                continue;
            id servers = state(store, key)[@"ServerAddresses"];
            if (![servers isKindOfClass:[NSArray class]])
                continue;
            for (id server in servers)
                if ([server isKindOfClass:[NSString class]] && ![dns containsObject:server])
                    [dns addObject:server];
        }
        CFRelease(store);
        return jsonCopy(links.allValues);
    }
}
char *eivro_applications(void) {
    @autoreleasepool {
        NSMutableArray *apps = [NSMutableArray array];
        NSArray *roots = @[
            @"/Applications", @"/System/Applications",
            [NSHomeDirectory() stringByAppendingPathComponent:@"Applications"]
        ];
        for (NSString *root in roots) {
            NSDirectoryEnumerator *entries = [[NSFileManager defaultManager]
                           enumeratorAtURL:[NSURL fileURLWithPath:root]
                includingPropertiesForKeys:nil
                                   options:NSDirectoryEnumerationSkipsHiddenFiles |
                                           NSDirectoryEnumerationSkipsPackageDescendants
                              errorHandler:nil];
            for (NSURL *url in entries) {
                if (entries.level > 3 || apps.count >= 2048) {
                    [entries skipDescendants];
                    continue;
                }
                if (![url.pathExtension isEqualToString:@"app"])
                    continue;
                NSBundle *bundle = [NSBundle bundleWithURL:url];
                NSString *path = bundle.executableURL.path;
                NSString *name = [bundle objectForInfoDictionaryKey:@"CFBundleDisplayName"];
                if (![name isKindOfClass:[NSString class]])
                    name = url.lastPathComponent.stringByDeletingPathExtension;
                if (path && name)
                    [apps addObject:@[ name, path ]];
            }
        }
        return jsonCopy(apps);
    }
}

// Only the installed root helper calls these. A journal is durably written by
// Rust before applying the plan. Restore compares owned field groups within each service.
char *eivro_settings_plan(uint16_t port, bool tun) {
    @autoreleasepool {
        SCPreferencesRef prefs = SCPreferencesCreate(NULL, CFSTR("Eivro"), NULL);
        if (!prefs)
            return NULL;
        SCDynamicStoreRef store = SCDynamicStoreCreate(NULL, CFSTR("Eivro plan"), NULL, NULL);
        if (!store) {
            CFRelease(prefs);
            return NULL;
        }
        NSString *primaryID = primary(store)[@"PrimaryService"];
        NSArray *services = CFBridgingRelease(SCNetworkServiceCopyAll(prefs));
        NSMutableArray *plan = [NSMutableArray array];
        for (id value in services) {
            SCNetworkServiceRef service = (__bridge SCNetworkServiceRef)value;
            if (!SCNetworkServiceGetEnabled(service))
                continue;
            NSString *identifier = (__bridge NSString *)SCNetworkServiceGetServiceID(service);
            // Keep scoped corporate DNS intact. Only replace the primary service's
            // resolver; named exits keep their own interface/DNS pairing.
            if (tun && ![identifier isEqualToString:primaryID])
                continue;
            CFStringRef type = tun ? kSCNetworkProtocolTypeDNS : kSCNetworkProtocolTypeProxies;
            SCNetworkProtocolRef protocol = SCNetworkServiceCopyProtocol(service, type);
            if (!protocol)
                continue;
            NSDictionary *original =
                (__bridge NSDictionary *)SCNetworkProtocolGetConfiguration(protocol);
            if (!original)
                original = @{};
            NSMutableDictionary *applied = [original mutableCopy];
            if (tun) {
                applied[(__bridge NSString *)kSCPropNetDNSServerAddresses] = @[ @"172.31.250.2" ];
            } else {
                [applied addEntriesFromDictionary:@{
                    @"HTTPEnable" : @1,
                    @"HTTPProxy" : @"127.0.0.1",
                    @"HTTPPort" : @(port),
                    @"HTTPSEnable" : @1,
                    @"HTTPSProxy" : @"127.0.0.1",
                    @"HTTPSPort" : @(port),
                    @"SOCKSEnable" : @1,
                    @"SOCKSProxy" : @"127.0.0.1",
                    @"SOCKSPort" : @(port),
                    @"ProxyAutoConfigEnable" : @0,
                    @"ProxyAutoDiscoveryEnable" : @0,
                    @"ExceptionsList" : @[ @"localhost", @"127.0.0.1", @"::1" ],
                    @"ExcludeSimpleHostnames" : @0
                }];
            }
            [plan addObject:@{
                @"service" : identifier,
                @"type" : (__bridge NSString *)type,
                @"before" : original,
                @"applied" : applied,
                @"before_enabled" : @((bool)SCNetworkProtocolGetEnabled(protocol)),
                @"applied_enabled" : @YES
            }];
            CFRelease(protocol);
        }
        CFRelease(store);
        CFRelease(prefs);
        return plan.count ? jsonCopy(plan) : NULL;
    }
}
static NSDictionary *restoredSettings(NSDictionary *entry, NSDictionary *current) {
    NSDictionary *before = entry[@"before"];
    NSDictionary *applied = entry[@"applied"];
    NSMutableDictionary *result = [current mutableCopy];
    // Endpoints are atomic groups: never combine another client's address
    // with our old port. Independent exceptions/search settings stay editable.
    NSArray *groups =
        [entry[@"type"] isEqualToString:(__bridge NSString *)kSCNetworkProtocolTypeDNS]
            ? @[ @[ @"ServerAddresses" ] ]
            : @[
                  @[ @"HTTPEnable", @"HTTPProxy", @"HTTPPort" ],
                  @[ @"HTTPSEnable", @"HTTPSProxy", @"HTTPSPort" ],
                  @[ @"SOCKSEnable", @"SOCKSProxy", @"SOCKSPort" ],
                  @[ @"ProxyAutoConfigEnable", @"ProxyAutoConfigURLString" ],
                  @[ @"ProxyAutoDiscoveryEnable" ], @[ @"ExceptionsList" ],
                  @[ @"ExcludeSimpleHostnames" ]
              ];
    for (NSArray *keys in groups) {
        bool owned = true;
        for (NSString *key in keys) {
            id actual = current[key], expected = applied[key];
            if (actual != expected && ![actual isEqual:expected]) {
                owned = false;
                break;
            }
        }
        if (!owned)
            continue;
        for (NSString *key in keys) {
            if (before[key])
                result[key] = before[key];
            else
                [result removeObjectForKey:key];
        }
    }
    return result;
}

bool eivro_settings_apply(const char *text, bool restore) {
    @autoreleasepool {
        if (!text)
            return false;
        NSData *data =
            [[NSString stringWithUTF8String:text] dataUsingEncoding:NSUTF8StringEncoding];
        id plan = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
        if (![plan isKindOfClass:[NSArray class]] || [plan count] > 128)
            return false;
        SCPreferencesRef prefs = SCPreferencesCreate(NULL, CFSTR("Eivro"), NULL);
        if (!prefs)
            return false;
        // Do not block the privileged session indefinitely on another writer.
        if (!SCPreferencesLock(prefs, false)) {
            CFRelease(prefs);
            return false;
        }
        bool ok = true;
        for (id entry in plan) {
            if (![entry isKindOfClass:[NSDictionary class]] ||
                ![entry[@"service"] isKindOfClass:[NSString class]] ||
                ![entry[@"before"] isKindOfClass:[NSDictionary class]] ||
                ![entry[@"applied"] isKindOfClass:[NSDictionary class]] ||
                ![entry[@"before_enabled"] isKindOfClass:[NSNumber class]] ||
                ![entry[@"applied_enabled"] isKindOfClass:[NSNumber class]]) {
                ok = false;
                break;
            }
            NSString *type = entry[@"type"];
            if (![type isEqualToString:(__bridge NSString *)kSCNetworkProtocolTypeDNS] &&
                ![type isEqualToString:(__bridge NSString *)kSCNetworkProtocolTypeProxies]) {
                ok = false;
                break;
            }
            SCNetworkServiceRef service =
                SCNetworkServiceCopy(prefs, (__bridge CFStringRef)entry[@"service"]);
            if (!service) {
                if (!restore)
                    ok = false;
                continue;
            }
            SCNetworkProtocolRef protocol =
                SCNetworkServiceCopyProtocol(service, (__bridge CFStringRef)type);
            CFRelease(service);
            if (!protocol) {
                if (!restore)
                    ok = false;
                continue;
            }
            NSDictionary *current =
                (__bridge NSDictionary *)SCNetworkProtocolGetConfiguration(protocol);
            if (!current)
                current = @{};
            bool unchanged =
                [current isEqualToDictionary:entry[restore ? @"applied" : @"before"]] &&
                SCNetworkProtocolGetEnabled(protocol) ==
                    [entry[restore ? @"applied_enabled" : @"before_enabled"] boolValue];
            if (restore) {
                NSDictionary *restored = restoredSettings(entry, current);
                ok = SCNetworkProtocolSetConfiguration(protocol,
                                                       (__bridge CFDictionaryRef)restored) &&
                     ok;
                if (unchanged)
                    ok = SCNetworkProtocolSetEnabled(protocol,
                                                     [entry[@"before_enabled"] boolValue]) &&
                         ok;
            } else if (unchanged) {
                ok = SCNetworkProtocolSetConfiguration(
                         protocol, (__bridge CFDictionaryRef)entry[@"applied"]) &&
                     ok;
                ok = SCNetworkProtocolSetEnabled(protocol, [entry[@"applied_enabled"] boolValue]) &&
                     ok;
            } else {
                ok = false;
            }
            CFRelease(protocol);
        }
        if (ok)
            ok = SCPreferencesCommitChanges(prefs) && SCPreferencesApplyChanges(prefs);
        SCPreferencesUnlock(prefs);
        CFRelease(prefs);
        return ok;
    }
}
const void *eivro_authorize(uint8_t *token) {
    AuthorizationRef auth = NULL;
    AuthorizationItem item = {kAuthorizationRightExecute, 0, NULL, 0};
    AuthorizationRights rights = {1, &item};
    const char *prompt =
        "Eivro: разрешить управление VPN и сетевыми настройками до завершения приложения.";
    AuthorizationItem context = {kAuthorizationEnvironmentPrompt, strlen(prompt), (void *)prompt,
                                 0};
    AuthorizationEnvironment environment = {1, &context};
    if (AuthorizationCreate(NULL, NULL, kAuthorizationFlagDefaults, &auth) !=
        errAuthorizationSuccess)
        return NULL;
    OSStatus result =
        AuthorizationCopyRights(auth, &rights, &environment,
                                kAuthorizationFlagInteractionAllowed |
                                    kAuthorizationFlagExtendRights | kAuthorizationFlagPreAuthorize,
                                NULL);
    AuthorizationExternalForm form;
    if (result != errAuthorizationSuccess ||
        AuthorizationMakeExternalForm(auth, &form) != errAuthorizationSuccess) {
        AuthorizationFree(auth, kAuthorizationFlagDestroyRights);
        return NULL;
    }
    _Static_assert(sizeof(form) == 32, "Authorization token ABI changed");
    memcpy(token, &form, sizeof(form));
    return auth;
}
bool eivro_verify_authorization(const uint8_t *token) {
    AuthorizationExternalForm form;
    memcpy(&form, token, sizeof(form));
    AuthorizationRef auth = NULL;
    if (AuthorizationCreateFromExternalForm(&form, &auth) != errAuthorizationSuccess)
        return false;
    AuthorizationItem item = {kAuthorizationRightExecute, 0, NULL, 0};
    AuthorizationRights rights = {1, &item};
    // Never extend rights in the root process: only verify the client's grant.
    bool ok = AuthorizationCopyRights(auth, &rights, NULL, kAuthorizationFlagDefaults, NULL) ==
              errAuthorizationSuccess;
    AuthorizationFree(auth, kAuthorizationFlagDefaults);
    return ok;
}
void eivro_authorization_free(const void *handle) {
    if (handle)
        AuthorizationFree(handle, kAuthorizationFlagDestroyRights);
}

@interface EivroDesktop : NSObject
@property(nonatomic) void (*callback)(void *, int, bool);
@property(nonatomic) void *context;
@property(nonatomic, strong) NSStatusItem *item;
@property(nonatomic, strong) NSMenuItem *toggle;
@property(nonatomic, strong) NSMenuItem *mainToggle;
@property(nonatomic, strong) NSMenu *previousMenu;
@property(nonatomic, strong) id sleepObserver;
@property(nonatomic, strong) id wakeObserver;
@property(nonatomic, strong) NSString *networkSignature;
@property(nonatomic) SCDynamicStoreRef store;
@property(nonatomic) CFRunLoopSourceRef source;
@end
@implementation EivroDesktop
- (void)show:(id)sender {
    (void)sender;
    self.callback(self.context, 0, true);
}
- (void)connect:(id)sender {
    (void)sender;
    self.callback(self.context, 1, true);
}
- (void)quit:(id)sender {
    (void)sender;
    self.callback(self.context, 2, true);
}
- (void)settings:(id)sender {
    (void)sender;
    self.callback(self.context, 8, true);
}
- (NSMenuItem *)action:(NSString *)title selector:(SEL)selector key:(NSString *)key {
    NSMenuItem *item = [[NSMenuItem alloc] initWithTitle:title action:selector keyEquivalent:key];
    item.target = self;
    return item;
}
- (void)networkChanged {
    NSDictionary *route = primary(self.store);
    NSString *name = route[@"PrimaryInterface"];
    if (![name isKindOfClass:[NSString class]])
        name = nil;
    if ([name hasPrefix:@"utun"])
        return;
    NSString *service = route[@"PrimaryService"];
    NSDictionary *dhcp = service ? CFBridgingRelease(SCDynamicStoreCopyDHCPInfo(
                                       self.store, (__bridge CFStringRef)service))
                                 : nil;
    NSData *servers =
        dhcp ? (__bridge NSData *)DHCPInfoGetOptionData((__bridge CFDictionaryRef)dhcp, 6) : nil;
    // Compare actual DHCP DNS, not notification counts: applying our own DNS
    // can publish another service notification without any uplink change.
    NSArray *addresses =
        name ? state(self.store, [NSString stringWithFormat:@"State:/Network/Interface/%@/IPv4",
                                                            name])[@"Addresses"]
             : nil;
    NSString *signature = [NSString
        stringWithFormat:@"%@/%@/%@/%@", name ? name : @"",
                         route[@"Router"] ? route[@"Router"] : @"", addresses ? addresses : @[],
                         servers ? [servers base64EncodedStringWithOptions:0] : @""];
    if (![signature isEqualToString:self.networkSignature]) {
        self.networkSignature = signature;
        self.callback(self.context, 3, name.length > 0);
    }
}
@end
static void networkCallback(SCDynamicStoreRef store, CFArrayRef keys, void *context) {
    (void)store;
    (void)keys;
    @autoreleasepool {
        EivroDesktop *desktop = (__bridge EivroDesktop *)context;
        [desktop networkChanged];
        desktop.callback(desktop.context, 5, true);
    }
}
void *eivro_desktop_start(void (*callback)(void *, int, bool), void *context) {
    @autoreleasepool {
        if (![NSThread isMainThread])
            return NULL;
        EivroDesktop *desktop = [EivroDesktop new];
        desktop.callback = callback;
        desktop.context = context;
        desktop.item =
            [[NSStatusBar systemStatusBar] statusItemWithLength:NSVariableStatusItemLength];
        desktop.item.button.image = [NSImage imageWithSystemSymbolName:@"network"
                                              accessibilityDescription:@"Eivro"];
        desktop.item.button.image.template = YES;
        NSMenu *menu = [NSMenu new];
        [menu addItem:[desktop action:@"Открыть Eivro" selector:@selector(show:) key:@""]];
        desktop.toggle = [desktop action:@"Подключиться" selector:@selector(connect:) key:@""];
        [menu addItem:desktop.toggle];
        [menu addItem:[NSMenuItem separatorItem]];
        [menu addItem:[desktop action:@"Настройки…" selector:@selector(settings:) key:@""]];
        [menu addItem:[desktop action:@"Завершить Eivro" selector:@selector(quit:) key:@""]];
        desktop.item.menu = menu;
        desktop.previousMenu = NSApp.mainMenu;
        NSMenu *main = desktop.previousMenu ? [desktop.previousMenu copy] : [NSMenu new];
        NSMenuItem *app = [NSMenuItem new];
        NSMenu *appMenu = [NSMenu new];
        [appMenu addItem:[desktop action:@"Открыть Eivro" selector:@selector(show:) key:@"0"]];
        [appMenu addItem:[desktop action:@"Настройки…" selector:@selector(settings:) key:@","]];
        desktop.mainToggle = [desktop action:@"Подключиться" selector:@selector(connect:) key:@""];
        [appMenu addItem:desktop.mainToggle];
        [appMenu addItem:[NSMenuItem separatorItem]];
        [appMenu addItem:[desktop action:@"Завершить Eivro" selector:@selector(quit:) key:@"q"]];
        app.submenu = appMenu;
        if (main.numberOfItems > 0)
            [main removeItemAtIndex:0];
        [main insertItem:app atIndex:0];
        NSApp.mainMenu = main;
        __weak EivroDesktop *weak = desktop;
        NSNotificationCenter *center = NSWorkspace.sharedWorkspace.notificationCenter;
        desktop.sleepObserver = [center addObserverForName:NSWorkspaceWillSleepNotification
                                                    object:nil
                                                     queue:NSOperationQueue.mainQueue
                                                usingBlock:^(NSNotification *note) {
                                                  (void)note;
                                                  EivroDesktop *d = weak;
                                                  if (d)
                                                      d.callback(d.context, 4, true);
                                                }];
        desktop.wakeObserver = [center addObserverForName:NSWorkspaceDidWakeNotification
                                                   object:nil
                                                    queue:NSOperationQueue.mainQueue
                                               usingBlock:^(NSNotification *note) {
                                                 (void)note;
                                                 EivroDesktop *d = weak;
                                                 if (d)
                                                     d.callback(d.context, 4, false);
                                               }];
        SCDynamicStoreContext config = {0, (__bridge void *)desktop, NULL, NULL, NULL};
        desktop.store = SCDynamicStoreCreate(NULL, CFSTR("Eivro events"), networkCallback, &config);
        bool listening = false;
        if (desktop.store) {
            NSArray *patterns = @[
                @"State:/Network/Global/IPv[46]", @"State:/Network/Service/.*/DNS",
                @"State:/Network/Service/.*/DHCP", @"State:/Network/Interface/.*/IPv[46]"
            ];
            if (SCDynamicStoreSetNotificationKeys(desktop.store, NULL,
                                                  (__bridge CFArrayRef)patterns)) {
                desktop.source = SCDynamicStoreCreateRunLoopSource(NULL, desktop.store, 0);
                if (desktop.source) {
                    CFRunLoopAddSource(CFRunLoopGetMain(), desktop.source, kCFRunLoopCommonModes);
                    listening = true;
                    [desktop networkChanged];
                }
            }
        }
        if (!listening)
            callback(context, 7, true);
        callback(context, 6, desktop.item != nil);
        return (__bridge_retained void *)desktop;
    }
}
void eivro_desktop_update(void *handle, bool running, bool wanted) {
    @autoreleasepool {
        EivroDesktop *desktop = (__bridge EivroDesktop *)handle;
        desktop.item.button.toolTip = running  ? @"Eivro — подключено"
                                      : wanted ? @"Eivro — подключение…"
                                               : @"Eivro — отключено";
        NSString *title = wanted ? @"Отключить" : @"Подключиться";
        desktop.toggle.title = title;
        desktop.mainToggle.title = title;
    }
}
void eivro_desktop_appearance(bool dark) {
    @autoreleasepool {
        NSApp.appearance =
            [NSAppearance appearanceNamed:dark ? NSAppearanceNameDarkAqua : NSAppearanceNameAqua];
    }
}
void eivro_desktop_stop(void *handle) {
    @autoreleasepool {
        EivroDesktop *desktop = (__bridge_transfer EivroDesktop *)handle;
        if (desktop.source) {
            CFRunLoopRemoveSource(CFRunLoopGetMain(), desktop.source, kCFRunLoopCommonModes);
            CFRelease(desktop.source);
        }
        if (desktop.store)
            CFRelease(desktop.store);
        NSNotificationCenter *center = NSWorkspace.sharedWorkspace.notificationCenter;
        if (desktop.sleepObserver)
            [center removeObserver:desktop.sleepObserver];
        if (desktop.wakeObserver)
            [center removeObserver:desktop.wakeObserver];
        [[NSStatusBar systemStatusBar] removeStatusItem:desktop.item];
        NSApp.mainMenu = desktop.previousMenu;
    }
}
