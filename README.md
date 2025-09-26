# ReqWebSocket

`Req` plugin for establishing WebSocket connections, using `Mint.WebSocket`.

## Usage

```elixir
resp =
  Req.new()
  |> ReqWebSocket.attach()
  |> Req.get!(into: :self, url: "wss://reqbin.org/")

message = receive do message -> message end
{:ok, resp, [ping: ""]} = ReqWebSocket.parse_message(resp, message)
{:ok, resp} = ReqWebSocket.send_frame(resp, :pong)
```
