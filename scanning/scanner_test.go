package scanning

import (
    "context"
    "testing"
    "time"
)

func TestScanner(t *testing.T) {
    tests := []struct {
        name    string
        target  string
        wantErr bool
    }{
        {
            name:    "صالح - موقع ويب",
            target:  "http://example.com",
            wantErr: false,
        },
        {
            name:    "غير صالح - هدف فارغ",
            target:  "",
            wantErr: true,
        },
        {
            name:    "غير صالح - URL غير صحيح",
            target:  "invalid://url",
            wantErr: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            scanner := NewScanner(&ScannerOptions{
                Target:     tt.target,
                Timeout:    time.Second * 30,
                Concurrent: 5,
            })

            ctx := context.Background()
            results, err := scanner.Run(ctx)

            if (err != nil) != tt.wantErr {
                t.Errorf("Scanner.Run() error = %v, wantErr %v", err, tt.wantErr)
                return
            }

            if !tt.wantErr && results == nil {
                t.Error("Scanner.Run() returned nil results")
            }
        })
    }
} 