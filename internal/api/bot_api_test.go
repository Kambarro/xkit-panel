package api
import "testing"
func TestValidBotToken(t *testing.T){
 good:=[]string{"123456789:AAHfiqksKZ8WmR2yS5N8xKjL9pQrT3vWxYz","123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"}
 bad:=[]string{"","abc:short","12345:tooshortsecret","123456789AAHfiqksKZ8WmR2yS5N8xKjL9pQrT3vWxYz","12a456:AAHfiqksKZ8WmR2yS5N8xKjL9pQrT3vWxYz","123456:AAHfiqksKZ8WmR2yS5N8xKjL9pQrT3vWxY!"}
 for _,tok:=range good{if !validBotToken(tok){t.Errorf("good token rejected: %s",tok)}}
 for _,tok:=range bad{if validBotToken(tok){t.Errorf("bad token accepted: %s",tok)}}
}
