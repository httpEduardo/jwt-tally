package main

import (
    "bufio"
    "encoding/base64"
    "encoding/json"
    "flag"
    "fmt"
    "os"
    "strings"
    "time"
)

type Claims map[string]interface{}

func decodeSegment(segment string) (map[string]interface{}, error) {
    data, err := base64.RawURLEncoding.DecodeString(segment)
    if err != nil {
        return nil, err
    }
    var payload map[string]interface{}
    if err := json.Unmarshal(data, &payload); err != nil {
        return nil, err
    }
    return payload, nil
}

func parseToken(token string) (map[string]interface{}, Claims, error) {
    parts := strings.Split(token, ".")
    if len(parts) < 2 {
        return nil, nil, fmt.Errorf("invalid token format")
    }
    header, err := decodeSegment(parts[0])
    if err != nil {
        return nil, nil, fmt.Errorf("header decode error: %w", err)
    }
    payload, err := decodeSegment(parts[1])
    if err != nil {
        return nil, nil, fmt.Errorf("payload decode error: %w", err)
    }
    return header, payload, nil
}

func formatJSON(data map[string]interface{}) string {
    pretty, err := json.MarshalIndent(data, "", "  ")
    if err != nil {
        return fmt.Sprintf("%v", data)
    }
    return string(pretty)
}

func claimString(claims Claims, key string) string {
    if value, ok := claims[key]; ok {
        return fmt.Sprintf("%v", value)
    }
    return ""
}

func main() {
    token := flag.String("token", "", "JWT to decode")
    file := flag.String("file", "", "File with one JWT per line")
    issuer := flag.String("issuer", "", "Expected issuer")
    audience := flag.String("audience", "", "Expected audience")
    flag.Parse()

    if *token == "" && *file == "" {
        fmt.Println("Provide --token or --file.")
        os.Exit(1)
    }

    handleToken := func(value string) {
        value = strings.TrimSpace(value)
        if value == "" {
            return
        }
        header, payload, err := parseToken(value)
        if err != nil {
            fmt.Println("\nToken error:", err)
            return
        }

        fmt.Println("\nHeader:")
        fmt.Println(formatJSON(header))
        fmt.Println("Payload:")
        fmt.Println(formatJSON(payload))

        fmt.Println("\nChecks:")
        if alg, ok := header["alg"]; ok {
            if alg == "none" {
                fmt.Println("- warn: alg=none")
            } else {
                fmt.Printf("- ok: alg=%v\n", alg)
            }
        } else {
            fmt.Println("- warn: missing alg")
        }

        if expRaw, ok := payload["exp"]; ok {
            expFloat, ok := expRaw.(float64)
            if ok {
                exp := time.Unix(int64(expFloat), 0)
                if time.Now().After(exp) {
                    fmt.Printf("- warn: token expired at %s\n", exp.Format(time.RFC3339))
                } else {
                    fmt.Printf("- ok: expires at %s\n", exp.Format(time.RFC3339))
                }
            } else {
                fmt.Println("- warn: exp is not a number")
            }
        } else {
            fmt.Println("- warn: missing exp")
        }

        if *issuer != "" {
            if claimString(payload, "iss") != *issuer {
                fmt.Printf("- warn: issuer mismatch (%s)\n", claimString(payload, "iss"))
            } else {
                fmt.Println("- ok: issuer matches")
            }
        }

        if *audience != "" {
            if claimString(payload, "aud") != *audience {
                fmt.Printf("- warn: audience mismatch (%s)\n", claimString(payload, "aud"))
            } else {
                fmt.Println("- ok: audience matches")
            }
        }
    }

    if *token != "" {
        handleToken(*token)
    }

    if *file != "" {
        fileHandle, err := os.Open(*file)
        if err != nil {
            fmt.Println("Failed to open file:", err)
            os.Exit(1)
        }
        defer fileHandle.Close()
        scanner := bufio.NewScanner(fileHandle)
        for scanner.Scan() {
            handleToken(scanner.Text())
        }
        if err := scanner.Err(); err != nil {
            fmt.Println("Failed reading file:", err)
        }
    }
}
