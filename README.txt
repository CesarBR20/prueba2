Ejecutar en el orden como estan los archivos enumerados.

- El primer ejecutable dara el token, token que dura 5 minutos.
- El segundo ejecutable dara un id_solictud (en caso de que de error cambiar los parametros de fecha, tipo_solicitud o tipo_comprobante)
* Una vez ejecutado el segundo codigo no volver a ejecutar a menos de que se hayan cambiado los parametros de fecha, tipo_solicitud o tipo_comprobante. En caso de ejecutar varias veces y no haber cambiado algun parametro de los mencionados, no se podra usar la misma combinacion de parametros mencionados anteriormente.
- El tercer ejecutable solamente sera para ver la verificacion del id que devuelve el segundo codigo. Este mostrara al principio 0 cfdis, estado de solicitud 1, y que fue aceptada. En este punto lo unico que queda es esperar unas cuantas horas hasta que el sat genere el estado de solicitud 3, y diga que ya esta listo para descargar, tambien mostrara el numero total de cfdis en el plazo establecido.
- El cuarto ejecutable descargara los cfdis en un zip

Todos los txt que genere cualquier ejecutable seran guardados en la carpeta correspondiente al cliente (en este caso unico, dirigirse a clientes/ y ahi se veran todos los clientes, al seleccionar el cliente deseado se mostrarn diversos archivos)

Archivos base para todos:

1. certificados: aqui estara la fiel convertida en .pem para poder interactuar con el SAT
2. paquetes: aqui se descargaran los cfdis del SAT
3. solicitudes: aqui estara el archivo .txt de id_solicitud
4. tokens: aqui se guardaran los tokens que se generen


Orden deseado para ejecutar los codigos .py

1_auth -> 2_req -> 3_verify

Despues de seguir este orden, no volver a ejecutar el 2_req. Ejectuar 1_auth -> 3_verify hasta que el estado de solicitud pase a ser 3. Cuando sea 3 ya se podran descargar los cdfis o metadata.
