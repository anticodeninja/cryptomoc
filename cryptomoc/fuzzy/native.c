#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_INPUT 255
#define BYTE_SIZE 256

#if !defined(MASK) || !defined(NONCE) || !defined(NONCE_LEN) || !defined(MAX_VARIETY)
#error All arguments should be passed
#endif

enum Codes
    {
     INCORRECT_OBJECT_START,
     INCORRECT_OBJECT_ID,
     INCORRECT_OBJECT_COLON,
     INCORRECT_OBJECT_COMMA,
     INCORRECT_OBJECT_END,
     INCORRECT_ARRAY_COMMA,
     INCORRECT_ARRAY_END,
     INCORRECT_VALUE_START,
     INCORRECT_VALUE_END,
     INCORRECT_STRING_ESCAPING,
     INCORRECT_STRING_UNICODE_ESCAPING,
     INCORRECT_STRING_END,
     INCORRECT_INTEGER_PART,
     INCORRECT_DECIMAL_PART,
     INCORRECT_EXPONENT_PART,
     INCORRECT_CONSTANT,
    };

char Messages[][100] =
    {
     "Incorrect object start",
     "Incorrect object id",
     "Incorrect object colon",
     "Incorrect object comma",
     "Incorrect object end",
     "Incorrect array comma",
     "Incorrect array end",
     "Incorrect value start",
     "Incorrect value end",
     "Incorrect string escaping",
     "Incorrect string unicode escaping",
     "Incorrect string end",
     "Incorrect integer part",
     "Incorrect decimal part",
     "Incorrect exponent part",
     "Incorrect constant",
     "Overlaped data",
    };

#ifdef DEBUG
#define RAISE(id) {\
        printf("%s: %d\n", Messages[id], (int)id);\
        if (validation_result == BYTE_SIZE) validation_result = id;\
        nonce[id] = 0;\
        return (size_t)(index + 1);\
    }
#else
#define RAISE(id) {\
        if (validation_result == BYTE_SIZE) validation_result = id;\
        nonce[id] = 0;\
        return (size_t)(index + 1);\
    }
#endif

char nonce[NONCE_LEN];

uint32_t table[BYTE_SIZE];
uint32_t validation_result;

__attribute__((visibility ("hidden")))
uint32_t init(uint32_t r) {
    for(int j = 0; j < 8; ++j) {
        r = (r & 1? 0: (uint32_t)0xEDB88320L) ^ r >> 1;
    }
    return r ^ (uint32_t)0xFF000000L;
}

__attribute__((visibility ("hidden")))
int is_space(char symbol);
__attribute__((visibility ("hidden")))
char get(char* input, size_t index, size_t len);
__attribute__((visibility ("hidden")))
size_t skip_space(char *input, size_t index, size_t len);
__attribute__((visibility ("hidden")))
size_t check_object(char *input, size_t index, size_t len);
__attribute__((visibility ("hidden")))
size_t check_array(char *input, size_t index, size_t len);
__attribute__((visibility ("hidden")))
size_t check_value(char *input, size_t index, size_t len);
__attribute__((visibility ("hidden")))
size_t check_string(char *input, size_t index, size_t len);
__attribute__((visibility ("hidden")))
size_t check_uchar(char *input, size_t index, size_t len);
__attribute__((visibility ("hidden")))
size_t check_number(char *input, size_t index, size_t len);
__attribute__((visibility ("hidden")))
size_t check_constant(char *input, size_t index, size_t len);

int is_space(char symbol) {
    return symbol == ' ' || symbol == '\t' || symbol == '\n' || symbol == '\r';
}

char get(char* input, size_t index, size_t len) {
    return index < len ? input[index] : 0;
}

size_t skip_space(char *input, size_t index, size_t len) {
    for (;index < len && is_space(get(input, index, len)); ++index) { }
    return index;
}

size_t check_object(char *input, size_t index, size_t len) {
    index = skip_space(input, index, len);
    if (get(input, index, len) != '{')
        RAISE(INCORRECT_OBJECT_START);
    index += 1;

    index = skip_space(input, index, len);
    if (get(input, index, len) == '}')
        return index + 1;

    for (;;) {
        index = skip_space(input, index, len);
        if (get(input, index, len) == 0)
            RAISE(INCORRECT_OBJECT_END);
        if (get(input, index, len) != '"')
            RAISE(INCORRECT_OBJECT_ID);

        index = check_string(input, index, len);

        index = skip_space(input, index, len);
        if (get(input, index, len) == 0)
            RAISE(INCORRECT_OBJECT_END);
        if (get(input, index, len) != ':')
            RAISE(INCORRECT_OBJECT_COLON);
        index += 1;

        index = check_value(input, index, len);

        index = skip_space(input, index, len);
        if (get(input, index, len) == '}')
            return index + 1;
        if (get(input, index, len) == 0)
            RAISE(INCORRECT_OBJECT_END);
        if (get(input, index, len) != ',')
            RAISE(INCORRECT_OBJECT_COMMA);
        index += 1;
    }

    return index;
}

size_t check_array(char *input, size_t index, size_t len) {
    // '[' is already checked
    index += 1;

    index = skip_space(input, index, len);
    if (get(input, index, len) == ']')
        return index + 1;

    for (;;) {
        index = check_value(input, index, len);

        index = skip_space(input, index, len);
        if (get(input, index, len) == ']')
            return index + 1;
        if (get(input, index, len) == 0)
            RAISE(INCORRECT_ARRAY_END);
        if (get(input, index, len) != ',')
            RAISE(INCORRECT_ARRAY_COMMA);
        index += 1;
    }

    return index;
}

size_t check_value(char *input, size_t index, size_t len) {
    index = skip_space(input, index, len);
    if (get(input, index, len) == 0)
        RAISE(INCORRECT_VALUE_END);
    if (get(input, index, len) == '"')
        return check_string(input, index, len);
    if (get(input, index, len) == '{')
        return check_object(input, index, len);
    if (get(input, index, len) == '[')
        return check_array(input, index, len);
    if (get(input, index, len) == '-' ||
        (get(input, index, len) >= '0' && get(input, index, len) <= '9'))
        return check_number(input, index, len);
    if (get(input, index, len) == 't' ||
        get(input, index, len) == 'f' ||
        get(input, index, len) == 'n')
        return check_constant(input, index, len);
    RAISE(INCORRECT_VALUE_START);
}

size_t check_string(char *input, size_t index, size_t len) {
    // '"' is already checked
    index += 1;

    for (;;) {
        if (get(input, index, len) == '"')
            return index + 1;
        if (get(input, index, len) == 0)
            RAISE(INCORRECT_STRING_END);

        if (get(input, index, len) == '\\') {
            index += 1;

            if (get(input, index, len) == '"' || get(input, index, len) == '\\' ||
                get(input, index, len) == '/' || get(input, index, len) == 'b' ||
                get(input, index, len) == 'f' || get(input, index, len) == 'n' ||
                get(input, index, len) == 'r' || get(input, index, len) == 't') {
                // Everything fine
                index += 1;
            } else if (get(input, index, len) == 'u') {
                index = check_uchar(input, index, len);
            } else {
                RAISE(INCORRECT_STRING_ESCAPING);
            }
        } else {
            index += 1;
        }
    }

    return index;
}

size_t check_uchar(char *input, size_t index, size_t len) {
    for (size_t i = 0; i < 4; ++i) {
        if ((get(input, index + i, len) >= '0' && get(input, index + i, len) <= '9') ||
            (get(input, index + i, len) >= 'a' && get(input, index + i, len) <= 'f') ||
            (get(input, index + i, len) >= 'A' && get(input, index + i, len) <= 'F')) {
            // Everything fine
        } else {
            RAISE(INCORRECT_STRING_UNICODE_ESCAPING);
        }
    }
    return index + 4;
}

size_t check_number(char *input, size_t index, size_t len) {
    index = skip_space(input, index, len);
    if (get(input, index, len) == '-')
        index += 1;
    if (get(input, index, len) == '0') {
        index += 1;
    } else if (get(input, index, len) >= '1' && get(input, index, len) <= '9') {
        index += 1;
        while (get(input, index, len) >= '0' &&
               get(input, index, len) <= '9')
            index += 1;
    } else {
        RAISE(INCORRECT_INTEGER_PART);
    }

    if (get(input, index, len) == '.') {
        index += 1;
        if (get(input, index, len) < '0' || get(input, index, len) > '9') {
            RAISE(INCORRECT_DECIMAL_PART);
        }
        while (index < len && get(input, index, len) >= '0' && get(input, index, len) <= '9') index += 1;
    }

    if (get(input, index, len) == 'e' || get(input, index, len) == 'E') {
        index += 1;
        if (get(input, index, len) == '-' || get(input, index, len) == '+') index += 1;
        if (get(input, index, len) < '0' || get(input, index, len) > '9') {
            RAISE(INCORRECT_EXPONENT_PART);
        }
        while (index < len && get(input, index, len) >= '0' && get(input, index, len) <= '9') index += 1;
    }

    return index;
}

size_t check_constant(char *input, size_t index, size_t len) {
    if (get(input, index, len) == 't') {
        if (get(input, ++index, len) != 'r') RAISE(INCORRECT_CONSTANT);
        if (get(input, ++index, len) != 'u') RAISE(INCORRECT_CONSTANT);
        if (get(input, ++index, len) != 'e') RAISE(INCORRECT_CONSTANT);
        return index;
    }

    if (get(input, index, len) == 'f') {
        if (get(input, ++index, len) != 'a') RAISE(INCORRECT_CONSTANT);
        if (get(input, ++index, len) != 'l') RAISE(INCORRECT_CONSTANT);
        if (get(input, ++index, len) != 's') RAISE(INCORRECT_CONSTANT);
        if (get(input, ++index, len) != 'e') RAISE(INCORRECT_CONSTANT);
        return index;
    }

    if (get(input, index, len) == 'n') {
        if (get(input, ++index, len) != 'u') RAISE(INCORRECT_CONSTANT);
        if (get(input, ++index, len) != 'l') RAISE(INCORRECT_CONSTANT);
        if (get(input, ++index, len) != 'l') RAISE(INCORRECT_CONSTANT);
        return index;
    }

    RAISE(INCORRECT_CONSTANT)
}

uint64_t check(char *input, size_t len) {
    for(size_t i = 0; i < BYTE_SIZE; ++i) {
        table[i] = init(i);
    }
    strncpy(nonce, NONCE, NONCE_LEN);
    validation_result = BYTE_SIZE;

#ifdef DEBUG
    printf("Mask: 0x%x\n", MASK);
#ifdef REFERENCE
    printf("Reference: 0x%x\n", (uint32_t)REFERENCE);
#endif
    printf("Input [%ld]: ", len);
    for(size_t i = 0; i < len; ++i) {
        printf("%c", input[i]);
    }
    printf("\nNonce: ");
    for(size_t i = 0; i < NONCE_LEN; ++i) {
        printf("0x%hhX ", nonce[i]);
    }
    printf("\n");
#endif

#ifdef REFERENCE
    if (len > MAX_INPUT) {
        len = MAX_INPUT;
    }

    size_t index = 0;
    while (index < len) {
        index = check_object(input, index, len);
    }

#else
    for(size_t i = 0; i < MAX_VARIETY; ++i) {
        if ((MASK & (1 << i)) != 0) {
            printf("%s: %d\n", Messages[i], (int)i);
            nonce[i] = 0;
        }
    }
#endif

#ifdef DEBUG
    printf("Nonce: ");
    for(size_t i = 0; i < NONCE_LEN; ++i) {
        printf("0x%hhX ", nonce[i]);
    }
    printf("\n");
#endif

    uint32_t reference = 0x00000000;
    uint32_t result = 0xFFFFFFFF;

    for(size_t i = 0; i < NONCE_LEN; ++i) {
        reference = table[(uint8_t)reference ^ (uint8_t)(nonce[i])] ^ reference >> 8;
        result = table[(uint8_t)result ^ (uint8_t)(nonce[i])] ^ result >> 8;
    }

    if (validation_result != BYTE_SIZE) {
        printf("%s\n", Messages[validation_result]);
    }

#ifdef DEBUG
    printf("Ref: 0x%08x\n", reference);
    printf("Res: 0x%08x\n", result);
#endif

#if defined(REFERENCE)
    if (validation_result == BYTE_SIZE) return 0x1FEA4BEEF;
    if (reference != REFERENCE) return 0x1DEADBEEF;
    return result;
#else
    uint64_t temp = reference;
    temp = (temp << 32) | result;
    return temp;
#endif
}
