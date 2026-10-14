# Phần phòng thủ TruongBao

`Gateway.decide` chỉ ra quyết định, không gọi tool hoặc đọc file. `policy.py`
kiểm tra peer/card/skill/audience/token, learner và scopes, lease, header replica,
mask, precondition, idempotency, rate window và chi phí theo TOOL_SPECS.

Policy cho phép truy vấn bình thường, không từ chối mọi câu hỏi. Các cụm từ
injection trong q/term không bị chặn chỉ vì người dùng đang hỏi về bảo mật;
content-shaped arguments và kết quả truy xuất được kiểm tra riêng.

`note_card`, `note_provenance`, `note_result` là hook nhận kết quả từ orchestrator
đáng tin cậy. Không gọi chúng với lời tự xác nhận của model. Registry card gốc
được verify bằng primitive của kit; dạng `{verified, skills}` chỉ được chấp nhận
khi trusted arena truyền vào note_card, để tương thích spar.

Orchestrator cần gọi note_result sau khi nhận kết quả thực; nếu không có hook
hoặc live ctx.leases, gateway từ chối get_frame/write thiếu chứng cứ thay vì đoán.
Kết quả ghi không rõ ràng được giữ trạng thái đã authorize; không retry mù.

Gateway không nhận ANSWER. `answer.prepare_answer` phải được caller gọi trước
khi phát ANSWER, kiểm tra citation/required fields, kết quả partial, redaction
và số học. Caller phải xử lý errors (tra cứu bổ sung hoặc abstain), không được
phát câu trả lời lỗi chỉ vì helper đã trả về một dict. Prompt cung cấp chính sách
cho harness dùng model; spar.py hiện không chạy prompt hoặc answer helper này.

Giới hạn: scanner là heuristic, không chứng minh nội dung không bị injection.
Grounding anchor chứng minh nguồn được truy xuất, không chứng minh mọi câu trong
prose là suy luận đúng. So sánh freshness phải dùng evidence; pin replica không
tự ngăn mọi mutation sau gateway. Sandbox kernel của kit cần macOS và chưa được
kiểm chứng trên máy Windows này.
