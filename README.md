# ReqWebSocket

`Req` plugin for establishing WebSocket connections, using `Mint.WebSocket`.

## Usage

```elixir
resp =
  Req.new()
  |> ReqWebSocket.attach()
  |> Req.get!(into: :self, url: "wss://echo.websocket.org/")

message = receive do message -> message end
{:ok, resp, [text: _]} = ReqWebSocket.parse_message(resp, message)

{:ok, resp} = ReqWebSocket.send_frame(resp, :ping)

message = receive do message -> message end
{:ok, resp, [pong: ""]} = ReqWebSocket.parse_message(resp, message)
```
