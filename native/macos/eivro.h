#pragma once
#include <stdbool.h>
#include <stdint.h>
void *eivro_desktop_start(void (*callback)(void *, int, bool), void *context);
void eivro_desktop_update(void *, bool, bool);
void eivro_desktop_stop(void *);
void eivro_desktop_appearance(bool dark);
char *eivro_interfaces(void);
char *eivro_uplink(void);
char *eivro_applications(void);
char *eivro_settings_plan(uint16_t, bool);
bool eivro_settings_apply(const char *, bool);
const void *eivro_authorize(uint8_t *);
bool eivro_verify_authorization(const uint8_t *);
void eivro_authorization_free(const void *);
