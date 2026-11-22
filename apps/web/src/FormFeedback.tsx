import type { ReactNode } from "react";

export type FormFeedbackValue = { text: string; role: "status" | "alert" };

export function FormFeedback({ feedback, children }: { feedback: FormFeedbackValue | null; children?: ReactNode }) {
  if (!feedback) return null;
  return <p role={feedback.role} className="form-message">{feedback.text}{children}</p>;
}
