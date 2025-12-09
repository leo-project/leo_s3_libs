.PHONY: deps test

REBAR := rebar3
APPS = erts kernel stdlib sasl crypto compiler inets mnesia public_key runtime_tools snmp syntax_tools tools xmerl webtool ssl
LIBS = _build/default/lib/leo_commons/ebin _build/default/lib/cowlib/ebin
PLT_FILE = .leo_s3_libs_dialyzer_plt
COMMON_PLT_FILE = .common_dialyzer_plt
DOT_FILE = leo_s3_libs.dot
CALL_GRAPH_FILE = leo_s3_libs.png

all: compile xref eunit
deps:
	@$(REBAR) deps
compile:
	@$(REBAR) compile
xref:
	@$(REBAR) xref
eunit:
	@$(REBAR) eunit
check_plt:
	@$(REBAR) compile
	dialyzer --check_plt --plt $(PLT_FILE) --apps $(APPS)
build_plt:
	@$(REBAR) compile
	dialyzer --build_plt --output_plt $(PLT_FILE) --apps $(LIBS)
dialyzer:
	@$(REBAR) compile
	dialyzer -Wno_return --plts $(PLT_FILE) $(COMMON_PLT_FILE) -r _build/default/lib/leo_s3_libs/ebin/ --dump_callgraph $(DOT_FILE) -Wrace_conditions | fgrep -v -f ./dialyzer.ignore-warnings
typer:
	typer --plt $(PLT_FILE) -I include/ -r src/
doc: compile
	@$(REBAR) edoc
callgraph: graphviz
	dot -Tpng -o$(CALL_GRAPH_FILE) $(DOT_FILE)
graphviz:
	$(if $(shell which dot),,$(error "To make the depgraph, you need graphviz installed"))
clean:
	@$(REBAR) clean
distclean:
	@rm -rf _build rebar.lock
	@$(REBAR) clean
