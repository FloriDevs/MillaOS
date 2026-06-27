#include <stddef.h>
#include <stdint.h>

// Declarations of kernel/shell functions we can use
extern "C" {
struct Time {
  uint8_t hour;
  uint8_t minute;
  uint8_t second;
};
Time get_time();
void put_pixel(int x, int y, uint32_t color);
void *malloc(uint32_t size);
char shell_scancode_to_ascii(uint8_t scancode, bool shift);
bool shell_read_file(const char *filename, char *buffer, uint32_t max_size);
void mpra_delay(int seconds);
void mpra_trigger_redraw();
}

// C++ linkage (defined without extern "C" in shell.cpp)
void itoa_light(int n, char *s);
void draw_rect_alpha(int x, int y, int w, int h, uint32_t color, uint8_t alpha);
void draw_string(int x, int y, const char *str, uint32_t color);

// Simple string functions
void string_copy(char *dest, const char *src) {
  int i = 0;
  while (src[i] != '\0') {
    dest[i] = src[i];
    i++;
  }
  dest[i] = '\0';
}

int string_length(const char *str) {
  int len = 0;
  while (str[len] != '\0')
    len++;
  return len;
}

bool string_compare_nocase(const char *s1, const char *s2) {
  int i = 0;
  while (s1[i] && s2[i]) {
    char c1 = s1[i];
    char c2 = s2[i];
    if (c1 >= 'A' && c1 <= 'Z')
      c1 = c1 - 'A' + 'a';
    if (c2 >= 'A' && c2 <= 'Z')
      c2 = c2 - 'A' + 'a';
    if (c1 != c2)
      return false;
    i++;
  }
  return s1[i] == '\0' && s2[i] == '\0';
}

// Token definition
enum TokenType {
  TOKEN_EOF,
  TOKEN_IDENTIFIER,
  TOKEN_KEYWORD,
  TOKEN_INT_LITERAL,
  TOKEN_STRING_LITERAL,
  TOKEN_BOOL_LITERAL,
  TOKEN_ASSIGN,    // =
  TOKEN_EQUAL,     // ==
  TOKEN_PLUS,      // +
  TOKEN_NOT,       // !
  TOKEN_SEMICOLON, // ;
  TOKEN_LPAREN,    // (
  TOKEN_RPAREN,    // )
  TOKEN_LBRACE,    // {
  TOKEN_RBRACE,    // }
  TOKEN_DOT,       // .
  TOKEN_COMMA      // ,
};

struct Token {
  TokenType type;
  char text[128];
  int int_val;
};

// Variable storage
struct Variable {
  char name[32];
  enum Type { VAR_INT, VAR_STRING, VAR_BOOL, VAR_GUI } type;
  int int_val;
  char string_val[128];
  bool bool_val;
  int gui_index; // index in the gui elements array
};

// GUI Element definition
enum GuiType { GUI_NONE, GUI_FRAME, GUI_LABEL, GUI_FIELD, GUI_BUTTON };

struct GuiElement {
  GuiType type;
  char name[32];
  char title[128];
  int size;
  int x, y, w, h;
  char value[128];
  int onclick_start_token;
  int onclick_end_token;
};

// Class definition
struct ClassDefinition {
  char name[32];
  int start_token;
  int end_token;
  char params[4][32];
  int param_count;
};

// Interpreter global state
struct InterpreterState {
  Token tokens[512];
  int token_count;

  Variable variables[64];
  int var_count;

  GuiElement gui_elements[32];
  int gui_count;

  ClassDefinition classes[16];
  int class_count;

  bool is_running;
  int active_field_idx; // currently focused text field for typing
  bool shift_pressed;
};

static InterpreterState state;

// Tokenizer
int tokenize(const char *source, Token *tokens, int max_tokens) {
  int count = 0;
  int i = 0;
  while (source[i] != '\0' && count < max_tokens) {
    char c = source[i];

    // Skip whitespace
    if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
      i++;
      continue;
    }

    // Skip comments
    if (c == '/' && source[i + 1] == '/') {
      while (source[i] != '\0' && source[i] != '\n' && source[i] != '\r') {
        i++;
      }
      continue;
    }

    // Semicolon
    if (c == ';') {
      tokens[count].type = TOKEN_SEMICOLON;
      tokens[count].text[0] = ';';
      tokens[count].text[1] = '\0';
      count++;
      i++;
      continue;
    }

    // Parentheses and braces
    if (c == '(') {
      tokens[count].type = TOKEN_LPAREN;
      tokens[count].text[0] = '(';
      tokens[count].text[1] = '\0';
      count++;
      i++;
      continue;
    }
    if (c == ')') {
      tokens[count].type = TOKEN_RPAREN;
      tokens[count].text[0] = ')';
      tokens[count].text[1] = '\0';
      count++;
      i++;
      continue;
    }
    if (c == '{') {
      tokens[count].type = TOKEN_LBRACE;
      tokens[count].text[0] = '{';
      tokens[count].text[1] = '\0';
      count++;
      i++;
      continue;
    }
    if (c == '}') {
      tokens[count].type = TOKEN_RBRACE;
      tokens[count].text[0] = '}';
      tokens[count].text[1] = '\0';
      count++;
      i++;
      continue;
    }
    if (c == '.') {
      tokens[count].type = TOKEN_DOT;
      tokens[count].text[0] = '.';
      tokens[count].text[1] = '\0';
      count++;
      i++;
      continue;
    }
    if (c == ',') {
      tokens[count].type = TOKEN_COMMA;
      tokens[count].text[0] = ',';
      tokens[count].text[1] = '\0';
      count++;
      i++;
      continue;
    }
    if (c == '+') {
      tokens[count].type = TOKEN_PLUS;
      tokens[count].text[0] = '+';
      tokens[count].text[1] = '\0';
      count++;
      i++;
      continue;
    }
    if (c == '!') {
      tokens[count].type = TOKEN_NOT;
      tokens[count].text[0] = '!';
      tokens[count].text[1] = '\0';
      count++;
      i++;
      continue;
    }

    // Equals / Compare
    if (c == '=') {
      if (source[i + 1] == '=') {
        tokens[count].type = TOKEN_EQUAL;
        tokens[count].text[0] = '=';
        tokens[count].text[1] = '=';
        tokens[count].text[2] = '\0';
        count++;
        i += 2;
      } else {
        tokens[count].type = TOKEN_ASSIGN;
        tokens[count].text[0] = '=';
        tokens[count].text[1] = '\0';
        count++;
        i++;
      }
      continue;
    }

    // Smart and normal double quotes for strings
    if (c == '"' || (uint8_t)c == 0xE2) {
      bool is_smart_quote = false;
      if ((uint8_t)c == 0xE2 && (uint8_t)source[i + 1] == 0x80 &&
          ((uint8_t)source[i + 2] == 0x9C || (uint8_t)source[i + 2] == 0x9D ||
           (uint8_t)source[i + 2] == 0x9E)) {
        is_smart_quote = true;
      }

      if (c == '"' || is_smart_quote) {
        int start_pos = i + (is_smart_quote ? 3 : 1);
        int len = 0;
        i = start_pos;
        while (source[i] != '\0') {
          if (source[i] == '"') {
            break;
          }
          if ((uint8_t)source[i] == 0xE2 && (uint8_t)source[i + 1] == 0x80 &&
              ((uint8_t)source[i + 2] == 0x9C ||
               (uint8_t)source[i + 2] == 0x9D ||
               (uint8_t)source[i + 2] == 0x9E)) {
            break;
          }
          if (len < 127) {
            tokens[count].text[len++] = source[i];
          }
          i++;
        }
        tokens[count].text[len] = '\0';
        tokens[count].type = TOKEN_STRING_LITERAL;
        count++;
        if (source[i] == '"')
          i++;
        else if ((uint8_t)source[i] == 0xE2)
          i += 3;
        continue;
      }
    }

    // Numeric literals
    if (c >= '0' && c <= '9') {
      int val = 0;
      int len = 0;
      while (source[i] >= '0' && source[i] <= '9') {
        val = val * 10 + (source[i] - '0');
        if (len < 127) {
          tokens[count].text[len++] = source[i];
        }
        i++;
      }
      tokens[count].text[len] = '\0';
      tokens[count].type = TOKEN_INT_LITERAL;
      tokens[count].int_val = val;
      count++;
      continue;
    }

    // Identifiers and Keywords (including hyphens)
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_') {
      int len = 0;
      while ((source[i] >= 'a' && source[i] <= 'z') ||
             (source[i] >= 'A' && source[i] <= 'Z') ||
             (source[i] >= '0' && source[i] <= '9') || source[i] == '_' ||
             source[i] == '-') {
        if (len < 127) {
          tokens[count].text[len++] = source[i];
        }
        i++;
      }
      tokens[count].text[len] = '\0';

      // Check if keyword
      if (string_compare_nocase(tokens[count].text, "public") ||
          string_compare_nocase(tokens[count].text, "class") ||
          string_compare_nocase(tokens[count].text, "string") ||
          string_compare_nocase(tokens[count].text, "int") ||
          string_compare_nocase(tokens[count].text, "boolean") ||
          string_compare_nocase(tokens[count].text, "mframe") ||
          string_compare_nocase(tokens[count].text, "mlable") ||
          string_compare_nocase(tokens[count].text, "mfield") ||
          string_compare_nocase(tokens[count].text, "mbutton") ||
          string_compare_nocase(tokens[count].text, "new") ||
          string_compare_nocase(tokens[count].text, "run") ||
          string_compare_nocase(tokens[count].text, "changetext") ||
          string_compare_nocase(tokens[count].text, "gettext") ||
          string_compare_nocase(tokens[count].text, "delay") ||
          string_compare_nocase(tokens[count].text, "if") ||
          string_compare_nocase(tokens[count].text, "else") ||
          string_compare_nocase(tokens[count].text, "while")) {
        tokens[count].type = TOKEN_KEYWORD;
      } else if (string_compare_nocase(tokens[count].text, "true") ||
                 string_compare_nocase(tokens[count].text, "false")) {
        tokens[count].type = TOKEN_BOOL_LITERAL;
        tokens[count].int_val =
            string_compare_nocase(tokens[count].text, "true") ? 1 : 0;
      } else {
        tokens[count].type = TOKEN_IDENTIFIER;
      }
      count++;
      continue;
    }

    i++;
  }

  if (count < max_tokens) {
    tokens[count].type = TOKEN_EOF;
    tokens[count].text[0] = '\0';
  }
  return count;
}

// Find classes in program
void find_classes(Token *tokens, int token_count) {
  state.class_count = 0;
  for (int i = 0; i < token_count; i++) {
    bool is_main = false;
    bool is_class = false;

    if (tokens[i].type == TOKEN_KEYWORD &&
        string_compare_nocase(tokens[i].text, "public")) {
      if (i + 2 < token_count && tokens[i + 1].type == TOKEN_IDENTIFIER &&
          string_compare_nocase(tokens[i + 1].text, "main") &&
          tokens[i + 2].type == TOKEN_KEYWORD &&
          string_compare_nocase(tokens[i + 2].text, "class")) {
        is_main = true;
        i += 2;
      }
    } else if (tokens[i].type == TOKEN_IDENTIFIER &&
               string_compare_nocase(tokens[i].text, "public")) {
      if (i + 2 < token_count && tokens[i + 1].type == TOKEN_IDENTIFIER &&
          string_compare_nocase(tokens[i + 1].text, "main") &&
          tokens[i + 2].type == TOKEN_KEYWORD &&
          string_compare_nocase(tokens[i + 2].text, "class")) {
        is_main = true;
        i += 2;
      }
    } else if (tokens[i].type == TOKEN_KEYWORD &&
               string_compare_nocase(tokens[i].text, "class")) {
      is_class = true;
    }

    if (is_main) {
      if (i + 1 < token_count && tokens[i + 1].type == TOKEN_LBRACE) {
        i++;
        ClassDefinition &cd = state.classes[state.class_count++];
        string_copy(cd.name, "main");
        cd.start_token = i + 1;
        cd.param_count = 0;
        int brace_depth = 1;
        int j = i + 1;
        while (j < token_count && brace_depth > 0) {
          if (tokens[j].type == TOKEN_LBRACE)
            brace_depth++;
          else if (tokens[j].type == TOKEN_RBRACE)
            brace_depth--;
          j++;
        }
        cd.end_token = j - 2;
        i = j - 1;
      }
    } else if (is_class) {
      if (i + 1 < token_count && tokens[i + 1].type == TOKEN_IDENTIFIER) {
        i++;
        ClassDefinition &cd = state.classes[state.class_count++];
        string_copy(cd.name, tokens[i].text);
        cd.param_count = 0;

        if (i + 1 < token_count && tokens[i + 1].type == TOKEN_LPAREN) {
          i += 2;
          while (i < token_count && tokens[i].type != TOKEN_RPAREN) {
            if (tokens[i].type == TOKEN_IDENTIFIER) {
              string_copy(cd.params[cd.param_count++], tokens[i].text);
            }
            i++;
          }
        }

        while (i < token_count && tokens[i].type != TOKEN_LBRACE) {
          i++;
        }

        if (tokens[i].type == TOKEN_LBRACE) {
          cd.start_token = i + 1;
          int brace_depth = 1;
          int j = i + 1;
          while (j < token_count && brace_depth > 0) {
            if (tokens[j].type == TOKEN_LBRACE)
              brace_depth++;
            else if (tokens[j].type == TOKEN_RBRACE)
              brace_depth--;
            j++;
          }
          cd.end_token = j - 2;
          i = j - 1;
        }
      }
    }
  }
}

// Expression evaluator
struct ExprResult {
  Variable::Type type;
  int int_val;
  char string_val[128];
  bool bool_val;
  int gui_index;
};

ExprResult evaluate_expression(Token *tokens, int start, int end,
                               Variable *local_vars, int local_var_count) {
  ExprResult res;
  res.type = Variable::VAR_INT;
  res.int_val = 0;
  res.string_val[0] = '\0';
  res.bool_val = false;
  res.gui_index = -1;

  if (start > end)
    return res;

  // Negation: !expr
  if (tokens[start].type == TOKEN_NOT) {
    ExprResult inner = evaluate_expression(tokens, start + 1, end, local_vars,
                                           local_var_count);
    res.type = Variable::VAR_BOOL;
    if (inner.type == Variable::VAR_BOOL) {
      res.bool_val = !inner.bool_val;
    } else if (inner.type == Variable::VAR_INT) {
      res.bool_val = !inner.int_val;
    }
    return res;
  }

  // getText.field-name
  if (tokens[start].type == TOKEN_KEYWORD &&
      string_compare_nocase(tokens[start].text, "getText")) {
    if (start + 2 <= end && tokens[start + 1].type == TOKEN_DOT &&
        tokens[start + 2].type == TOKEN_IDENTIFIER) {
      const char *field_name = tokens[start + 2].text;
      int gui_idx = -1;
      for (int k = 0; k < state.gui_count; k++) {
        if (string_compare_nocase(state.gui_elements[k].name, field_name)) {
          gui_idx = k;
          break;
        }
      }
      res.type = Variable::VAR_STRING;
      if (gui_idx != -1 && state.gui_elements[gui_idx].type == GUI_FIELD) {
        string_copy(res.string_val, state.gui_elements[gui_idx].value);
      } else {
        res.string_val[0] = '\0';
      }
      return res;
    }
  }

  // Binary operations: + (concat/add), = or == (equality comparison in
  // conditions)
  int op_idx = -1;
  for (int k = start; k <= end; k++) {
    if (tokens[k].type == TOKEN_PLUS || tokens[k].type == TOKEN_ASSIGN ||
        tokens[k].type == TOKEN_EQUAL) {
      op_idx = k;
      break;
    }
  }

  if (op_idx != -1) {
    ExprResult left = evaluate_expression(tokens, start, op_idx - 1, local_vars,
                                          local_var_count);
    ExprResult right = evaluate_expression(tokens, op_idx + 1, end, local_vars,
                                           local_var_count);

    if (tokens[op_idx].type == TOKEN_PLUS) {
      if (left.type == Variable::VAR_STRING ||
          right.type == Variable::VAR_STRING) {
        res.type = Variable::VAR_STRING;
        char l_str[128];
        char r_str[128];
        if (left.type == Variable::VAR_STRING) {
          string_copy(l_str, left.string_val);
        } else if (left.type == Variable::VAR_INT) {
          itoa_light(left.int_val, l_str);
        } else if (left.type == Variable::VAR_BOOL) {
          string_copy(l_str, left.bool_val ? "true" : "false");
        } else {
          l_str[0] = '\0';
        }

        if (right.type == Variable::VAR_STRING) {
          string_copy(r_str, right.string_val);
        } else if (right.type == Variable::VAR_INT) {
          itoa_light(right.int_val, r_str);
        } else if (right.type == Variable::VAR_BOOL) {
          string_copy(r_str, right.bool_val ? "true" : "false");
        } else {
          r_str[0] = '\0';
        }

        string_copy(res.string_val, l_str);
        int l_len = string_length(res.string_val);
        if (l_len < 127) {
          string_copy(res.string_val + l_len, r_str);
        }
      } else if (left.type == Variable::VAR_INT &&
                 right.type == Variable::VAR_INT) {
        res.type = Variable::VAR_INT;
        res.int_val = left.int_val + right.int_val;
      }
      return res;
    } else if (tokens[op_idx].type == TOKEN_ASSIGN ||
               tokens[op_idx].type == TOKEN_EQUAL) {
      res.type = Variable::VAR_BOOL;
      if (left.type == Variable::VAR_INT && right.type == Variable::VAR_INT) {
        res.bool_val = (left.int_val == right.int_val);
      } else if (left.type == Variable::VAR_BOOL &&
                 right.type == Variable::VAR_BOOL) {
        res.bool_val = (left.bool_val == right.bool_val);
      } else if (left.type == Variable::VAR_STRING &&
                 right.type == Variable::VAR_STRING) {
        res.bool_val = string_compare_nocase(left.string_val, right.string_val);
      } else {
        res.bool_val = false;
      }
      return res;
    }
  }

  if (start == end) {
    Token &t = tokens[start];
    if (t.type == TOKEN_INT_LITERAL) {
      res.type = Variable::VAR_INT;
      res.int_val = t.int_val;
      return res;
    }
    if (t.type == TOKEN_STRING_LITERAL) {
      res.type = Variable::VAR_STRING;
      string_copy(res.string_val, t.text);
      return res;
    }
    if (t.type == TOKEN_BOOL_LITERAL) {
      res.type = Variable::VAR_BOOL;
      res.bool_val = (t.int_val != 0);
      return res;
    }
    if (t.type == TOKEN_IDENTIFIER) {
      if (local_vars != nullptr) {
        for (int k = 0; k < local_var_count; k++) {
          if (string_compare_nocase(local_vars[k].name, t.text)) {
            res.type = local_vars[k].type;
            res.int_val = local_vars[k].int_val;
            string_copy(res.string_val, local_vars[k].string_val);
            res.bool_val = local_vars[k].bool_val;
            res.gui_index = local_vars[k].gui_index;
            return res;
          }
        }
      }
      for (int k = 0; k < state.var_count; k++) {
        if (string_compare_nocase(state.variables[k].name, t.text)) {
          res.type = state.variables[k].type;
          res.int_val = state.variables[k].int_val;
          string_copy(res.string_val, state.variables[k].string_val);
          res.bool_val = state.variables[k].bool_val;
          res.gui_index = state.variables[k].gui_index;
          return res;
        }
      }
    }
  }

  return res;
}

int execute_statements(Token *tokens, int start, int end,
                       Variable *local_vars = nullptr,
                       int local_var_count = 0) {
  int i = start;
  while (i <= end) {
    if (tokens[i].type == TOKEN_SEMICOLON) {
      i++;
      continue;
    }

    // if statement
    if (tokens[i].type == TOKEN_KEYWORD &&
        string_compare_nocase(tokens[i].text, "if")) {
      int j = i + 1;
      while (j <= end && tokens[j].type != TOKEN_LPAREN)
        j++;
      int cond_start = j + 1;
      int paren_depth = 1;
      j++;
      while (j <= end && paren_depth > 0) {
        if (tokens[j].type == TOKEN_LPAREN)
          paren_depth++;
        else if (tokens[j].type == TOKEN_RPAREN)
          paren_depth--;
        j++;
      }
      int cond_end = j - 2;

      ExprResult cond_res = evaluate_expression(tokens, cond_start, cond_end,
                                                local_vars, local_var_count);
      bool cond_val = false;
      if (cond_res.type == Variable::VAR_BOOL)
        cond_val = cond_res.bool_val;
      else if (cond_res.type == Variable::VAR_INT)
        cond_val = (cond_res.int_val != 0);

      while (j <= end && tokens[j].type != TOKEN_LBRACE)
        j++;
      int true_start = j + 1;
      int brace_depth = 1;
      j++;
      while (j <= end && brace_depth > 0) {
        if (tokens[j].type == TOKEN_LBRACE)
          brace_depth++;
        else if (tokens[j].type == TOKEN_RBRACE)
          brace_depth--;
        j++;
      }
      int true_end = j - 2;

      bool has_else = false;
      int else_start = -1;
      int else_end = -1;
      if (j <= end && tokens[j].type == TOKEN_KEYWORD &&
          string_compare_nocase(tokens[j].text, "else")) {
        has_else = true;
        j++;
        while (j <= end && tokens[j].type != TOKEN_LBRACE)
          j++;
        else_start = j + 1;
        brace_depth = 1;
        j++;
        while (j <= end && brace_depth > 0) {
          if (tokens[j].type == TOKEN_LBRACE)
            brace_depth++;
          else if (tokens[j].type == TOKEN_RBRACE)
            brace_depth--;
          j++;
        }
        else_end = j - 2;
      }

      if (cond_val) {
        execute_statements(tokens, true_start, true_end, local_vars,
                           local_var_count);
      } else if (has_else) {
        execute_statements(tokens, else_start, else_end, local_vars,
                           local_var_count);
      }

      i = j;
      continue;
    }

    // while statement
    if (tokens[i].type == TOKEN_KEYWORD &&
        string_compare_nocase(tokens[i].text, "while")) {
      int j = i + 1;
      while (j <= end && tokens[j].type != TOKEN_LPAREN)
        j++;
      int cond_start = j + 1;
      int paren_depth = 1;
      j++;
      while (j <= end && paren_depth > 0) {
        if (tokens[j].type == TOKEN_LPAREN)
          paren_depth++;
        else if (tokens[j].type == TOKEN_RPAREN)
          paren_depth--;
        j++;
      }
      int cond_end = j - 2;

      while (j <= end && tokens[j].type != TOKEN_LBRACE)
        j++;
      int body_start = j + 1;
      int brace_depth = 1;
      j++;
      while (j <= end && brace_depth > 0) {
        if (tokens[j].type == TOKEN_LBRACE)
          brace_depth++;
        else if (tokens[j].type == TOKEN_RBRACE)
          brace_depth--;
        j++;
      }
      int body_end = j - 2;

      int loop_count = 0;
      while (loop_count < 1000) {
        ExprResult cond_res = evaluate_expression(tokens, cond_start, cond_end,
                                                  local_vars, local_var_count);
        bool cond_val = false;
        if (cond_res.type == Variable::VAR_BOOL)
          cond_val = cond_res.bool_val;
        else if (cond_res.type == Variable::VAR_INT)
          cond_val = (cond_res.int_val != 0);

        if (!cond_val)
          break;

        execute_statements(tokens, body_start, body_end, local_vars,
                           local_var_count);
        loop_count++;
      }

      i = j;
      continue;
    }

    // delay(time);
    if (tokens[i].type == TOKEN_KEYWORD &&
        string_compare_nocase(tokens[i].text, "delay")) {
      if (i + 3 <= end && tokens[i + 1].type == TOKEN_LPAREN) {
        int j = i + 2;
        while (j <= end && tokens[j].type != TOKEN_RPAREN)
          j++;
        ExprResult time_res = evaluate_expression(tokens, i + 2, j - 1,
                                                  local_vars, local_var_count);
        int seconds = 0;
        if (time_res.type == Variable::VAR_INT)
          seconds = time_res.int_val;

        mpra_delay(seconds);

        i = j + 2;
        continue;
      }
    }

    // changeText.text-name("new text");
    if (tokens[i].type == TOKEN_KEYWORD &&
        string_compare_nocase(tokens[i].text, "changeText")) {
      if (i + 4 <= end && tokens[i + 1].type == TOKEN_DOT &&
          tokens[i + 2].type == TOKEN_IDENTIFIER &&
          tokens[i + 3].type == TOKEN_LPAREN) {
        const char *label_name = tokens[i + 2].text;
        int j = i + 4;
        while (j <= end && tokens[j].type != TOKEN_RPAREN)
          j++;
        ExprResult text_res = evaluate_expression(tokens, i + 4, j - 1,
                                                  local_vars, local_var_count);

        for (int k = 0; k < state.gui_count; k++) {
          if (string_compare_nocase(state.gui_elements[k].name, label_name)) {
            if (text_res.type == Variable::VAR_STRING) {
              string_copy(state.gui_elements[k].value, text_res.string_val);
            } else if (text_res.type == Variable::VAR_INT) {
              itoa_light(text_res.int_val, state.gui_elements[k].value);
            } else if (text_res.type == Variable::VAR_BOOL) {
              string_copy(state.gui_elements[k].value,
                          text_res.bool_val ? "true" : "false");
            }
            break;
          }
        }

        mpra_trigger_redraw();

        i = j + 2;
        continue;
      }
    }

    // run.classname("your data");
    if (tokens[i].type == TOKEN_KEYWORD &&
        string_compare_nocase(tokens[i].text, "run")) {
      if (i + 4 <= end && tokens[i + 1].type == TOKEN_DOT &&
          tokens[i + 2].type == TOKEN_IDENTIFIER &&
          tokens[i + 3].type == TOKEN_LPAREN) {
        const char *classname = tokens[i + 2].text;
        int j = i + 4;
        ExprResult args[4];
        int arg_count = 0;
        int arg_start = j;
        while (j <= end && tokens[j].type != TOKEN_RPAREN) {
          if (tokens[j].type == TOKEN_COMMA) {
            if (arg_count < 4) {
              args[arg_count++] = evaluate_expression(
                  tokens, arg_start, j - 1, local_vars, local_var_count);
            }
            arg_start = j + 1;
          }
          j++;
        }
        if (j > arg_start && arg_count < 4) {
          args[arg_count++] = evaluate_expression(tokens, arg_start, j - 1,
                                                  local_vars, local_var_count);
        }

        int class_idx = -1;
        for (int k = 0; k < state.class_count; k++) {
          if (string_compare_nocase(state.classes[k].name, classname)) {
            class_idx = k;
            break;
          }
        }

        if (class_idx != -1) {
          ClassDefinition &cd = state.classes[class_idx];
          Variable params_vars[4];
          int local_count = cd.param_count;
          if (local_count > arg_count)
            local_count = arg_count;
          for (int k = 0; k < local_count; k++) {
            string_copy(params_vars[k].name, cd.params[k]);
            params_vars[k].type =
                (args[k].type == Variable::VAR_INT)    ? Variable::VAR_INT
                : (args[k].type == Variable::VAR_BOOL) ? Variable::VAR_BOOL
                                                       : Variable::VAR_STRING;
            params_vars[k].int_val = args[k].int_val;
            string_copy(params_vars[k].string_val, args[k].string_val);
            params_vars[k].bool_val = args[k].bool_val;
          }

          execute_statements(tokens, cd.start_token, cd.end_token, params_vars,
                             local_count);
        }

        i = j + 2;
        continue;
      }
    }

    // button-name.doonclick{ ... }
    if (tokens[i].type == TOKEN_IDENTIFIER && i + 3 <= end &&
        tokens[i + 1].type == TOKEN_DOT &&
        string_compare_nocase(tokens[i + 2].text, "doonclick") &&
        tokens[i + 3].type == TOKEN_LBRACE) {
      const char *btn_name = tokens[i].text;
      int j = i + 4;
      int brace_depth = 1;
      while (j <= end && brace_depth > 0) {
        if (tokens[j].type == TOKEN_LBRACE)
          brace_depth++;
        else if (tokens[j].type == TOKEN_RBRACE)
          brace_depth--;
        j++;
      }
      int click_start = i + 4;
      int click_end = j - 2;

      for (int k = 0; k < state.gui_count; k++) {
        if (string_compare_nocase(state.gui_elements[k].name, btn_name)) {
          state.gui_elements[k].onclick_start_token = click_start;
          state.gui_elements[k].onclick_end_token = click_end;
          break;
        }
      }

      i = j;
      continue;
    }

    // GUI Element methods (Size, add)
    if (tokens[i].type == TOKEN_IDENTIFIER && i + 2 <= end &&
        tokens[i + 1].type == TOKEN_DOT &&
        tokens[i + 2].type == TOKEN_IDENTIFIER) {
      const char *gui_var_name = tokens[i].text;
      const char *method_name = tokens[i + 2].text;

      if (string_compare_nocase(method_name, "Size")) {
        if (i + 6 <= end && tokens[i + 3].type == TOKEN_LPAREN &&
            tokens[i + 5].type == TOKEN_COMMA) {
          int j = i + 6;
          while (j <= end && tokens[j].type != TOKEN_RPAREN)
            j++;
          ExprResult x_res = evaluate_expression(tokens, i + 4, i + 4,
                                                 local_vars, local_var_count);
          ExprResult y_res = evaluate_expression(tokens, i + 6, j - 1,
                                                 local_vars, local_var_count);

          for (int k = 0; k < state.gui_count; k++) {
            if (string_compare_nocase(state.gui_elements[k].name,
                                      gui_var_name)) {
              if (state.gui_elements[k].type == GUI_FRAME) {
                state.gui_elements[k].w = x_res.int_val;
                state.gui_elements[k].h = y_res.int_val;
              }
              break;
            }
          }
          i = j + 2;
          continue;
        }
      } else if (string_compare_nocase(method_name, "add")) {
        if (i + 5 <= end && tokens[i + 3].type == TOKEN_LPAREN &&
            tokens[i + 5].type == TOKEN_RPAREN) {
          const char *elem_name = tokens[i + 4].text;
          int frame_idx = -1;
          for (int k = 0; k < state.gui_count; k++) {
            if (string_compare_nocase(state.gui_elements[k].name,
                                      gui_var_name)) {
              frame_idx = k;
              break;
            }
          }
          int elem_idx = -1;
          for (int k = 0; k < state.gui_count; k++) {
            if (string_compare_nocase(state.gui_elements[k].name, elem_name)) {
              elem_idx = k;
              break;
            }
          }

          if (frame_idx != -1 && elem_idx != -1) {
            int current_y_offset = 40;
            for (int k = 0; k < state.gui_count; k++) {
              if (state.gui_elements[k].type != GUI_FRAME &&
                  state.gui_elements[k].y >= current_y_offset) {
                current_y_offset =
                    state.gui_elements[k].y + state.gui_elements[k].h + 10;
              }
            }
            state.gui_elements[elem_idx].x = 20;
            state.gui_elements[elem_idx].y = current_y_offset;
            state.gui_elements[elem_idx].w =
                state.gui_elements[frame_idx].w - 40;
            if (state.gui_elements[elem_idx].type == GUI_FIELD) {
              state.gui_elements[elem_idx].h = 24;
            } else if (state.gui_elements[elem_idx].type == GUI_BUTTON) {
              state.gui_elements[elem_idx].h = 28;
            } else if (state.gui_elements[elem_idx].type == GUI_LABEL) {
              state.gui_elements[elem_idx].h = 16;
            }
          }
          i = i + 7;
          continue;
        }
      }
    }

    // Variable declaration
    bool is_decl = false;
    Variable::Type decl_type = Variable::VAR_INT;
    GuiType decl_gui_type = GUI_NONE;

    if (tokens[i].type == TOKEN_KEYWORD) {
      if (string_compare_nocase(tokens[i].text, "int")) {
        is_decl = true;
        decl_type = Variable::VAR_INT;
      } else if (string_compare_nocase(tokens[i].text, "string")) {
        is_decl = true;
        decl_type = Variable::VAR_STRING;
      } else if (string_compare_nocase(tokens[i].text, "boolean")) {
        is_decl = true;
        decl_type = Variable::VAR_BOOL;
      } else if (string_compare_nocase(tokens[i].text, "mframe")) {
        is_decl = true;
        decl_type = Variable::VAR_GUI;
        decl_gui_type = GUI_FRAME;
      } else if (string_compare_nocase(tokens[i].text, "mlable")) {
        is_decl = true;
        decl_type = Variable::VAR_GUI;
        decl_gui_type = GUI_LABEL;
      } else if (string_compare_nocase(tokens[i].text, "mfield")) {
        is_decl = true;
        decl_type = Variable::VAR_GUI;
        decl_gui_type = GUI_FIELD;
      } else if (string_compare_nocase(tokens[i].text, "mbutton")) {
        is_decl = true;
        decl_type = Variable::VAR_GUI;
        decl_gui_type = GUI_BUTTON;
      }
    }

    if (is_decl) {
      if (i + 1 <= end && tokens[i + 1].type == TOKEN_IDENTIFIER) {
        const char *var_name = tokens[i + 1].text;
        i += 2;

        int var_idx = state.var_count++;
        Variable &v = state.variables[var_idx];
        string_copy(v.name, var_name);
        v.type = decl_type;
        v.int_val = 0;
        v.string_val[0] = '\0';
        v.bool_val = false;
        v.gui_index = -1;

        if (decl_type == Variable::VAR_GUI) {
          int g_idx = state.gui_count++;
          v.gui_index = g_idx;
          GuiElement &g = state.gui_elements[g_idx];
          g.type = decl_gui_type;
          string_copy(g.name, var_name);
          g.title[0] = '\0';
          g.value[0] = '\0';
          g.size = 0;
          g.x = g.y = g.w = g.h = 0;
          g.onclick_start_token = -1;
          g.onclick_end_token = -1;
        }

        if (i <= end && tokens[i].type == TOKEN_ASSIGN) {
          i++;
          if (tokens[i].type == TOKEN_KEYWORD &&
              string_compare_nocase(tokens[i].text, "new")) {
            i++;
            if (tokens[i].type == TOKEN_KEYWORD && i + 3 <= end &&
                tokens[i + 1].type == TOKEN_LPAREN) {
              int j = i + 2;
              while (j <= end && tokens[j].type != TOKEN_RPAREN)
                j++;
              ExprResult init_res = evaluate_expression(
                  tokens, i + 2, j - 1, local_vars, local_var_count);

              int g_idx = v.gui_index;
              if (g_idx != -1) {
                if (decl_gui_type == GUI_FRAME || decl_gui_type == GUI_LABEL ||
                    decl_gui_type == GUI_BUTTON) {
                  string_copy(state.gui_elements[g_idx].title,
                              init_res.string_val);
                  if (decl_gui_type == GUI_LABEL) {
                    string_copy(state.gui_elements[g_idx].value,
                                init_res.string_val);
                  }
                } else if (decl_gui_type == GUI_FIELD) {
                  state.gui_elements[g_idx].size = init_res.int_val;
                  state.gui_elements[g_idx].value[0] = '\0';
                }
              }
              i = j + 2;
            }
          } else {
            int j = i;
            while (j <= end && tokens[j].type != TOKEN_SEMICOLON)
              j++;
            ExprResult expr_res = evaluate_expression(
                tokens, i, j - 1, local_vars, local_var_count);
            v.int_val = expr_res.int_val;
            string_copy(v.string_val, expr_res.string_val);
            v.bool_val = expr_res.bool_val;
            i = j + 1;
          }
        } else if (i <= end && tokens[i].type == TOKEN_SEMICOLON) {
          i++;
        }
        continue;
      }
    }

    // Variable assignment
    if (tokens[i].type == TOKEN_IDENTIFIER && i + 1 <= end &&
        tokens[i + 1].type == TOKEN_ASSIGN) {
      const char *var_name = tokens[i].text;
      int j = i + 2;
      while (j <= end && tokens[j].type != TOKEN_SEMICOLON)
        j++;
      ExprResult expr_res = evaluate_expression(tokens, i + 2, j - 1,
                                                local_vars, local_var_count);

      bool found = false;
      if (local_vars != nullptr) {
        for (int k = 0; k < local_var_count; k++) {
          if (string_compare_nocase(local_vars[k].name, var_name)) {
            local_vars[k].int_val = expr_res.int_val;
            string_copy(local_vars[k].string_val, expr_res.string_val);
            local_vars[k].bool_val = expr_res.bool_val;
            found = true;
            break;
          }
        }
      }

      if (!found) {
        for (int k = 0; k < state.var_count; k++) {
          if (string_compare_nocase(state.variables[k].name, var_name)) {
            state.variables[k].int_val = expr_res.int_val;
            string_copy(state.variables[k].string_val, expr_res.string_val);
            state.variables[k].bool_val = expr_res.bool_val;
            break;
          }
        }
      }

      i = j + 1;
      continue;
    }

    i++;
  }
  return i;
}

// Shell-facing APIs
extern "C" {

bool mpra_is_running() { return state.is_running; }

const char *mpra_get_window_title() {
  for (int k = 0; k < state.gui_count; k++) {
    if (state.gui_elements[k].type == GUI_FRAME) {
      return state.gui_elements[k].title;
    }
  }
  return "MPra Program";
}

int mpra_get_window_w() {
  for (int k = 0; k < state.gui_count; k++) {
    if (state.gui_elements[k].type == GUI_FRAME) {
      return state.gui_elements[k].w > 200 ? state.gui_elements[k].w : 200;
    }
  }
  return 400;
}

int mpra_get_window_h() {
  for (int k = 0; k < state.gui_count; k++) {
    if (state.gui_elements[k].type == GUI_FRAME) {
      return state.gui_elements[k].h > 200 ? state.gui_elements[k].h : 200;
    }
  }
  return 400;
}

void mpra_run_file(const char *filename) {
  // Reset state
  state.token_count = 0;
  state.var_count = 0;
  state.gui_count = 0;
  state.class_count = 0;
  state.active_field_idx = -1;
  state.shift_pressed = false;

  // Read file content
  static char code_buf[4096];
  code_buf[0] = '\0';
  if (!shell_read_file(filename, code_buf, sizeof(code_buf) - 1)) {
    state.is_running = false;
    return;
  }

  // Tokenize
  state.token_count = tokenize(code_buf, state.tokens, 500);

  // Find all classes
  find_classes(state.tokens, state.token_count);

  // Find and execute the "main" class
  int main_idx = -1;
  for (int k = 0; k < state.class_count; k++) {
    if (string_compare_nocase(state.classes[k].name, "main")) {
      main_idx = k;
      break;
    }
  }

  if (main_idx != -1) {
    state.is_running = true;
    execute_statements(state.tokens, state.classes[main_idx].start_token,
                       state.classes[main_idx].end_token);
  } else {
    state.is_running = false;
  }
}

void mpra_draw_content(int x, int y, int w, int h) {
  // Background area (below title bar)
  int cy = y + 28;

  // Draw all non-frame elements relative to the window
  for (int k = 0; k < state.gui_count; k++) {
    GuiElement &g = state.gui_elements[k];
    if (g.type == GUI_LABEL) {
      draw_string(x + g.x, cy + g.y, g.value, 0x000000);
    } else if (g.type == GUI_FIELD) {
      // White background field
      draw_rect_alpha(x + g.x, cy + g.y, g.w, g.h, 0xFFFFFF, 255);
      // Gray border
      draw_rect_alpha(x + g.x, cy + g.y, g.w, 1, 0x999999, 255);
      draw_rect_alpha(x + g.x, cy + g.y, 1, g.h, 0x999999, 255);
      draw_rect_alpha(x + g.x, cy + g.y + g.h - 1, g.w, 1, 0xDDDDDD, 255);
      draw_rect_alpha(x + g.x + g.w - 1, cy + g.y, 1, g.h, 0xDDDDDD, 255);

      // Display text inside field
      draw_string(x + g.x + 5, cy + g.y + 6, g.value, 0x000000);

      // Cursor if active
      if (state.active_field_idx == k) {
        Time t = get_time();
        if (t.second % 2 == 0) {
          int txt_len = string_length(g.value);
          draw_rect_alpha(x + g.x + 5 + txt_len * 8, cy + g.y + 4, 2, 14,
                          0x000000, 255);
        }
      }
    } else if (g.type == GUI_BUTTON) {
      extern int mouse_x;
      extern int mouse_y;
      bool hover = (mouse_x >= x + g.x && mouse_x < x + g.x + g.w &&
                    mouse_y >= cy + g.y && mouse_y < cy + g.y + g.h);
      uint32_t btn_col = hover ? 0xDDDDDD : 0xCCCCCC;
      draw_rect_alpha(x + g.x, cy + g.y, g.w, g.h, btn_col, 255);

      // Button border
      draw_rect_alpha(x + g.x, cy + g.y, g.w, 1, 0x999999, 255);
      draw_rect_alpha(x + g.x, cy + g.y, 1, g.h, 0x999999, 255);
      draw_rect_alpha(x + g.x, cy + g.y + g.h - 1, g.w, 1, 0x444444, 255);
      draw_rect_alpha(x + g.x + g.w - 1, cy + g.y, 1, g.h, 0x444444, 255);

      // Text centered
      int text_w = string_length(g.title) * 8;
      int text_x = x + g.x + (g.w - text_w) / 2;
      int text_y = cy + g.y + (g.h - 8) / 2;
      draw_string(text_x, text_y, g.title, 0x000000);
    }
  }
}

void mpra_handle_click(int x, int y) {
  // Click was inside the MPra window content
  // Check which element was clicked
  state.active_field_idx = -1; // reset focus

  for (int k = 0; k < state.gui_count; k++) {
    GuiElement &g = state.gui_elements[k];
    if (g.type == GUI_BUTTON) {
      if (x >= g.x && x < g.x + g.w && y >= g.y && y < g.y + g.h) {
        // Execute click action
        if (g.onclick_start_token != -1) {
          execute_statements(state.tokens, g.onclick_start_token,
                             g.onclick_end_token);
        }
        break;
      }
    } else if (g.type == GUI_FIELD) {
      if (x >= g.x && x < g.x + g.w && y >= g.y && y < g.y + g.h) {
        state.active_field_idx = k;
        break;
      }
    }
  }
}

void mpra_handle_key(uint8_t scancode) {
  if (scancode == 0x2A || scancode == 0x36) {
    state.shift_pressed = true;
    return;
  }
  if (scancode == (0x2A | 0x80) || scancode == (0x36 | 0x80)) {
    state.shift_pressed = false;
    return;
  }

  if (!(scancode & 0x80)) { // Key press
    if (state.active_field_idx != -1) {
      GuiElement &g = state.gui_elements[state.active_field_idx];
      int len = string_length(g.value);
      if (scancode == 0x0E) { // Backspace
        if (len > 0) {
          g.value[len - 1] = '\0';
        }
      } else {
        char ascii = shell_scancode_to_ascii(scancode, state.shift_pressed);
        if (ascii >= 32 && ascii <= 126 && len < 127) {
          g.value[len] = ascii;
          g.value[len + 1] = '\0';
        }
      }
    }
  }
}

void mpra_close() { state.is_running = false; }
}
