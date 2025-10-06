-- schema.sql
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email VARCHAR(255) UNIQUE NOT NULL,
  profile_data JSONB DEFAULT '{}'::jsonb,
  profile_completeness DECIMAL(3,2) DEFAULT 0.00,
  onboarding_status VARCHAR(50) DEFAULT 'started',
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

CREATE TABLE conversations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  started_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  completed_at TIMESTAMP WITH TIME ZONE,
  messages JSONB DEFAULT '[]'::jsonb,
  current_step VARCHAR(100) DEFAULT 'introduction',
  status VARCHAR(20) DEFAULT 'active',
  questions_asked INTEGER DEFAULT 0,
  questions_answered INTEGER DEFAULT 0,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

CREATE TABLE documents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  filename VARCHAR(255) NOT NULL,
  file_path VARCHAR(500) NOT NULL,
  file_size_bytes INTEGER,
  mime_type VARCHAR(100),
  processing_status VARCHAR(20) DEFAULT 'pending',
  extracted_data JSONB DEFAULT '{}'::jsonb,
  uploaded_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  processed_at TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

CREATE TABLE ocr_results (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  document_id UUID REFERENCES documents(id) ON DELETE CASCADE,
  extracted_text TEXT,
  uploaded_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  processed_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_conversations_user_id ON conversations(user_id);
CREATE INDEX idx_conversations_status ON conversations(status);
CREATE INDEX idx_documents_user_id ON documents(user_id);

-- trigger to auto-update updated_at
CREATE OR REPLACE FUNCTION trigger_set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER set_updated_at_users
BEFORE UPDATE ON users FOR EACH ROW
EXECUTE FUNCTION trigger_set_updated_at();

CREATE TRIGGER set_updated_at_conversations
BEFORE UPDATE ON conversations FOR EACH ROW
EXECUTE FUNCTION trigger_set_updated_at();

CREATE TRIGGER set_updated_at_documents
BEFORE UPDATE ON documents FOR EACH ROW
EXECUTE FUNCTION trigger_set_updated_at();
