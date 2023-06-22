"""
This type stub file was generated by pyright.
"""

import supervisor.medusa.producers as producers

RCS_ID = ...
unquote = ...
class default_handler:
    valid_commands = ...
    IDENT = ...
    directory_defaults = ...
    default_file_producer = producers.file_producer
    def __init__(self, filesystem) -> None:
        ...
    
    hit_counter = ...
    def __repr__(self): # -> str:
        ...
    
    def match(self, request): # -> Literal[1]:
        ...
    
    def handle_request(self, request): # -> None:
        ...
    
    def set_content_type(self, path, request): # -> None:
        ...
    
    def status(self): # -> simple_producer:
        ...
    


IF_MODIFIED_SINCE = ...
USER_AGENT = ...
CONTENT_TYPE = ...
get_header = ...
get_header_match = ...
def get_extension(path): # -> Literal['']:
    ...
