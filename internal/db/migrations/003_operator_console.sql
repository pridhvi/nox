ALTER TABLE sessions ADD COLUMN enabled_tools TEXT NOT NULL DEFAULT '[]';
ALTER TABLE sessions ADD COLUMN tool_parameters TEXT NOT NULL DEFAULT '{}';
ALTER TABLE sessions ADD COLUMN runner_options TEXT NOT NULL DEFAULT '{}';
