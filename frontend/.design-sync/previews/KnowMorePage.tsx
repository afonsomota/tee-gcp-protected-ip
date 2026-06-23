// Authored preview — the static "how your privacy is protected" explainer page.
// Fully self-contained: only an onBack callback. Renders the real shipped page.
import { KnowMorePage } from "tee-journal-frontend";

/** The full explainer page (enclave, image digest, key binding, operator table). */
export const Default = () => <KnowMorePage onBack={() => {}} />;
