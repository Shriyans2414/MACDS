# Execution Bridge Server Container

FROM alpine

RUN mkdir -p /opt/macds_exec

COPY execute_action.sh /opt/macds_exec/
RUN chmod +x /opt/macds_exec/execute_action.sh

CMD ["sleep", "10000"]
