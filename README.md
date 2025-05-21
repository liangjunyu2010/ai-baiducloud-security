---
title: AI内容安全
keywords: [higress, AI, security, ai-baiducloud-security]
description: 百度云大模型内容安全检测Higess插件
---

## 功能说明
通过对接百度云大模型内容安全的输入输出检测，保障AI应用内容合法合规。

## 运行属性

插件执行阶段：`默认阶段`
插件执行优先级：`300`

## 配置说明
| Name | Type | Requirement | Default | Description                                          |
| ------------ | ------------ | ------------ | ------------ |------------------------------------------------------|
| `serviceName` | string | requried | - | 服务名                                                  |
| `servicePort` | string | requried | - | 服务端口                                                 |
| `serviceHost` | string | requried | - | 百度云endpoint的域名 默认 : afd.bj.baidubce.com , 私有化可填写具体地址 |
| `accessKey` | string | requried | - | 百度云AK                                                |
| `secretKey` | string | requried | - | 百度云SK                                                |
| `checkRequest` | bool | optional | false | 检查提问内容是否合规                                           |
| `checkResponse` | bool | optional | false | 检查大模型的回答内容是否合规，生效时会使流式响应变为非流式                        |
| `requestCheckService` | string | optional | /rcs/llm/input/analyze | 内容安全输入检测服务具体路径                                       |
| `responseCheckService` | string | optional | /rcs/llm/output/analyze | 内容安全输出检测服务具体路径                                       |
| `requestContentJsonPath` | string | optional | `messages.@reverse.0.content` | 指定要检测内容在请求body中的jsonpath                             |
| `responseContentJsonPath` | string | optional | `choices.0.message.content` | 指定要检测内容在响应body中的jsonpath                             |
| `responseStreamContentJsonPath` | string | optional | `choices.0.delta.content` | 指定要检测内容在流式响应body中的jsonpath                           |
| `denyCode` | int | optional | 200 | 指定内容非法时的响应状态码                                        |
| `denyMessage` | string | optional | openai格式的流式/非流式响应 | 指定内容非法时的响应内容                                         |
| `timeout` | int | optional | 2000 | 调用内容安全服务时的超时时间                                       |

补充说明一下 `denyMessage`，对非法请求的处理逻辑为：
- 如果配置了 `denyMessage`，返回内容为 `denyMessage` 配置内容，格式为openai格式的流式/非流式响应
- 如果没有配置 `denyMessage`，优先返回内容安全的建议回答，格式为openai格式的流式/非流式响应
- 如果内容安全未返回建议的回答，返回内容为内置的兜底回答，内容为`"很抱歉，我无法回答您的问题"`，格式为openai格式的流式/非流式响应

## 配置示例
### 前提条件
由于插件中需要调用百度云内容安全服务，所以需要先创建一个DNS类型的服务，例如：

![](https://bj.bcebos.com/v1/safe-sig/opinit/open_source/higress/img/higress_service.png)

### 检测输入内容是否合规

```yaml
accessKey: "********"
checkRequest: true
requestCheckService: "/rcs/llm/input/analyze"
responseCheckService: "/rcs/llm/output/analyze"
secretKey: "********"
serviceHost: "afd.bj.baidubce.com"
serviceName: "safe.dns"
servicePort: 443
```

### 检测输入与输出是否合规

```yaml
accessKey: "********"
checkRequest: true
checkResponse: true
requestCheckService: "/rcs/llm/input/analyze"
responseCheckService: "/rcs/llm/output/analyze"
secretKey: "********"
serviceHost: "afd.bj.baidubce.com"
serviceName: "safe.dns"
servicePort: 443
```

## 可观测
### Metric
ai-baiducloud-security 插件提供了以下监控指标：
- `ai_sec_request_deny`: 请求内容安全检测失败请求数
- `ai_sec_response_deny`: 模型回答安全检测失败请求数

### Trace
如果开启了链路追踪，ai-baiducloud-security 插件会在请求 span 中添加以下 attributes:
- `ai_sec_riskaction`: 表示请求命中的风险类型

## 请求示例
```bash
curl http://localhost/v1/chat/completions \
-H "Content-Type: application/json" \
-d '{
  "model": "ernie-4.0-8k",
  "messages": [
    {
      "role": "user",
      "content": "这是一段非法内容"
    }
  ]
}'
```

请求内容会被发送到百度云内容安全服务进行检测，如果请求内容检测结果为非法，网关将返回形如以下的回答：

```json
{
  "id": "chatcmpl-E45zRLc5hUCxhsda4ODEhjvkEycC9",
  "object": "chat.completion",
  "model": "ai-baiducloud-security",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "抱歉，作为一个人工智能语言模型，我还没有学习学会如何回答这个问题，我会继续学习，为您提供更加优质的服务。"
      },
      "logprobs": null,
      "finish_reason": "stop"
    }
  ],
  "usage": {
    "prompt_tokens": 0,
    "completion_tokens": 0,
    "total_tokens": 0
  }
}
```