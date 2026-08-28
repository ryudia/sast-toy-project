import ast

def process_safe(user_input):
    ast.literal_eval(user_input)