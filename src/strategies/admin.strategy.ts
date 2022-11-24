import {AuthenticationStrategy} from '@loopback/authentication';
import {HttpErrors, Request} from '@loopback/rest';
import {UserProfile} from '@loopback/security';
import {AutenticacionService} from '../services';
import parseBearerToken from 'parse-bearer-token';
import {service} from '@loopback/core';

export class EstrategiaAdministrador implements AuthenticationStrategy{
  name: string ='admin';

  constructor(
    @service(AutenticacionService)
    public servicioAutenticacion: AutenticacionService
  ){

  }

  async authenticate(request: Request): Promise<UserProfile | undefined>{
    let token = parseBearerToken(request);
    if(token){
      let datos = this.servicioAutenticacion.ValidarTokenJWT(token);
      if(datos){
        let perfil : UserProfile = Object.assign({
          nombre: datos.data.nombres
        });
        return perfil;
      }else{
        throw new HttpErrors[401]("El token no es válido");
      }
    }else{
      throw new HttpErrors[401]("NO está incluido el token");
    }
  }
}
