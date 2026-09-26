# CodePilot Local

Ứng dụng desktop offline cho **LM Studio + Qwen2.5-Coder**, tập trung vào hội thoại và code agent. Model chỉ “đề xuất” tool; ứng dụng mới là phần kiểm tra schema, phân quyền, thực thi, ghi log và hiển thị kết quả.

## Tính năng

- Giao diện desktop tiếng Việt, streaming Markdown và code block có nút Copy.
- Kết nối tự động tới LM Studio OpenAI-compatible API.
- Ba chế độ: **Hội thoại**, **Agent**, **Lập kế hoạch**.
- Tool file/project: đọc, tìm kiếm, tạo, sửa, patch, xóa, project map, tìm symbol.
- Tool terminal/Git/test/build, tiến trình nền và memory của project.
- Web search (`Brave API` nếu có key, DuckDuckGo fallback), web fetch và HTTP request có chống SSRF cơ bản.
- MCP qua stdio hoặc Streamable HTTP.
- AI có thể gọi tối đa 3 subagent read-only theo mỗi lượt: explorer, reviewer, researcher, tester.
- Tool `ask_user`: model phải hỏi khi thiếu thông tin thay vì bịa.
- Lịch sử session, dừng lượt chạy, giới hạn bước và log đã redact secret.
- Không hiển thị tool protocol/JSON thô trong câu trả lời.
- Qwen Q3 thường phát `<call>` thay vì `tool_calls` chuẩn; app có lớp tương thích nhưng **mặc định để tắt** vì đây là quyền thay đổi trạng thái. Bật trong Settings → Agent sau khi bạn hiểu và xác nhận; lớp này vẫn kiểm tra allowlist/schema.

## Yêu cầu

- Windows 10/11 x64.
- Node.js 22 trở lên để chạy bản nguồn.
- LM Studio đã mở ít nhất một lần để tạo model catalog và CLI.
- Model text đã được LM Studio nhận diện.

Preset được khuyến nghị cho **GTX 1050 Ti 4 GB** là **Qwen3 4B — GTX 1050 Ti 4GB**. App không tự tải model; người dùng tải GGUF `Q4_K_M` trong LM Studio rồi chọn preset trong **Settings → Mô hình**.

Preset này điền cấu hình an toàn: context LM Studio `2048`, max output `2048`, ngân sách ngữ cảnh `8000` chars, Flash Attention bật, tối đa `1` subagent và không chạy song song. Có thể đổi sang preset Qwen2.5 Coder 3B nếu Qwen3 bị OOM.

Model cũ `qwen2.5-coder-14b-instruct` vẫn dùng được nhưng không phù hợp để chạy toàn bộ trên VRAM 4 GB; phần lớn model sẽ bị offload sang RAM/CPU.

### Preset thử nghiệm Qwen3.8 4B

Đã có preset **Qwen3.8 4B Distilled (Ma7ee7) — thinking, thử nghiệm** cho các bản GGUF `Q4_K_M` của repo `Ma7ee7/Qwen3.8_4B_Distilled_GGUF`. Preset dùng kiến trúc Qwen3, context `2048`, max output `2048`, Flash Attention bật, tối đa `6` bước và tắt subagent để giảm áp lực lên GTX 1050 Ti. Model bật thinking nên nên thử **Chat** trước; nếu muốn dùng Agent, hãy tăng subagent sau khi đã load ổn định.

Đây là model community distillation, không phải bản phát hành chính thức của Qwen.

## Chạy lần đầu

Cách nhanh nhất cho người mới: double-click **`START-HERE.cmd`**.

Hoặc chạy thủ công:

```powershell
cd D:\Coder_locally
npm.cmd install
npm.cmd start
```

Nếu `npm.cmd exec -- electron --version` bị ngắt khi tải, chạy script có resume thay vì tải lại từ đầu:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\install-electron-binary.ps1
```

Trong ứng dụng:

1. Chọn **Workspace** (thư mục dự án). Mọi file tool mặc định chỉ nằm trong workspace này.
2. Bấm **Kiểm tra kết nối**.
3. Nếu báo chưa chạy, bấm **Bật LM Studio Server**. App chạy `lms server start --port 1234`.
4. Trong **Settings → Mô hình**, chọn preset **Qwen3 4B — GTX 1050 Ti 4GB**, kiểm tra ID model rồi bấm **Load model**. App gửi cấu hình context `2048` và Flash Attention; nếu LM Studio báo không hỗ trợ Flash Attention, tắt tùy chọn này.
5. Bắt đầu chat.

LM Studio CLI thường nằm tại:

```text
C:\Users\<tên-bạn>\.lmstudio\bin\lms.exe
```

Nếu chưa có, app có nút cài qua `npx lmstudio install-cli`. Cũng có thể bật thủ công trong **LM Studio → Developer → Start Server**.

## MCP

Trong **Settings → MCP**, nhập JSON, ví dụ:

```json
{
  "playwright": {
    "command": "npx",
    "args": ["-y", "@playwright/mcp@latest"],
    "cwd": "D:\\Coder_locally"
  },
  "remote-example": {
    "url": "https://example.com/mcp",
    "headers": {
      "Authorization": "Bearer YOUR_TOKEN"
    }
  }
}
```

Bấm **Reload MCP**. Tool MCP là dữ liệu bên ngoài không đáng tin; server có giới hạn tên, schema, timeout, kích thước result và chặn endpoint mạng nội bộ qua web tool.

## Chế độ phân quyền

Mặc định app ở chế độ **Tự động** theo lựa chọn ban đầu:

- Đọc/ghi/xóa chỉ trong workspace.
- Terminal có thể chạy code của project và vì vậy vẫn là vùng rủi ro.
- Subagent chỉ đọc, không được sửa file hoặc sinh subagent tiếp.
- Có thể đổi sang **Hỏi trước** trong Settings để duyệt tool thay đổi.

Không hiểu “tự động” là sandbox hệ điều hành. Một lệnh shell trong workspace vẫn có thể chạm hệ thống, đọc credential hoặc gọi mạng. Chỉ bật Automatic khi bạn tin project.

## Kiểm thử và đóng gói

```powershell
npm.cmd test
npm.cmd run check
npm.cmd run pack
npm.cmd run dist
```

- `pack`: tạo bản unpacked trong `release/`.
- `dist`: tạo trình cài đặt Windows NSIS trong `release/`.

## Git backup

Sau khi source đã qua test, double-click `BACKUP-GIT.cmd` để tạo local Git backup commit. Script không push lên remote; cần URL và quyền Git riêng nếu bạn muốn sync lên máy chủ khác.

## Xử lý nhanh khi model trả lỗi

1. Xem pill trạng thái model và mở Activity panel.
2. Giảm số tool bằng cách dùng chế độ Chat/Plan hoặc chia câu hỏi.
3. Nạp Q4_K_M nếu Q3 hay chọn sai tool.
4. Tăng context cần đủ VRAM; context quá cao có thể làm model chậm hoặc không load.
5. Nếu model hỏi thiếu dữ liệu, trả lời hộp thoại `ask_user` thay vì đoán.
6. Xem `Settings → General` hoặc log gần nhất để kiểm tra kết nối.
