use std::{any, sync::{Arc, RwLock}};

use actix_web::{web::{self, Data}, App, HttpRequest, HttpResponse, HttpServer, Resource};
use bytes::Bytes;
use reqwest::{Body, Method};
use futures::stream::StreamExt;

use dotenv::dotenv;
use serde_derive::Deserialize;

use std::future::Future;
use std::pin::Pin;

type AsyncFn = fn(HttpRequest) -> Pin<Box<dyn Future<Output = Result<(), HttpResponse>>>>;

#[derive(Clone)]
struct Filter {
    filters: Arc<RwLock<Vec<AsyncFn>>>
}

impl Filter {
    fn new() -> Self {
        Filter {
            filters: Arc::new(RwLock::new(Vec::new())),
        }
    }

    fn add(&self, filter: AsyncFn) -> Self {
        let mut filters = self.filters.write().unwrap();
        filters.push(filter);

        self.clone() 
    }

    async fn run(&self, _req: &HttpRequest) -> Result<bool, HttpResponse> {
        let mut filters = self.filters.write().unwrap();
        for filter in filters.iter() {
            let cloned_req = _req.clone();
            
            if let Err(response) = Box::pin(filter(cloned_req)).await {
                return Err(response);
            }
        }
        Ok(true) 
    }
}

async fn default_filter(_req: HttpRequest) -> Result<(), HttpResponse> {
    return Ok(())
}

async fn send_request(uri: String, req: HttpRequest, mut payload: web::Payload) -> HttpResponse {
    let client = reqwest::Client::new();

    let _method = match req.method().as_str() {
        "GET" => Method::GET,
        "POST" => Method::POST,
        "PUT" => Method::PUT,
        "DELETE" => Method::DELETE,
        "PATCH" => Method::PATCH,
        _ => Method::OPTIONS
    };

    let mut body = web::BytesMut::new();

    while let Some(chunk) = payload.next().await {
        let _chunk = chunk.unwrap();
        body.extend_from_slice(&_chunk);
    }

    let _body = Body::from(Bytes::from(body));

    let res = client.request(_method, uri)
                    .header("X-Custom-Header", "Mt API Gateway")
                    .body(_body)
                    .send().await;

    let body_bytes = res.expect("Internal service error").text().await.unwrap().to_string().into_bytes();

    let data_result: serde_json::Value = if body_bytes.is_empty() {
        serde_json::json!({}) // Return a empty JSON
    } else {
        serde_json::from_slice(&body_bytes).unwrap_or_else(|_| serde_json::json!({}))
    };
    

    return HttpResponse::Ok().json(data_result);
}

async fn handle_request(_req: HttpRequest, mut payload: web::Payload, filters: web::Data<Arc<Filter>>) -> HttpResponse {
    let service_name = std::env::var("PRINCIPAL_SERVICE_NAME").expect("PRINCIPAL_SERVICE_NAME must be set.");
    let service_address = std::env::var("PRINCIPAL_SERVICE_ADDRESS").expect("PRINCIPAL_SERVICE_NAME must be set.");
    
    let path = _req.path().to_string();
    let parts: Vec<&str> = path.split('/').collect();

    if parts.len() < 2 {
        return HttpResponse::NotFound().body("Invalid request URI");
    }

    let uri_service_name = parts[1];

    if !service_name.eq(uri_service_name) {
        return HttpResponse::NotFound().body("Service not found");
    }

    // Create a new URI based on the resolved address
    let mut address = service_address;
    if !address.starts_with("http://") && !address.starts_with("https://") {
        address = format!("https://{}", address);
    }
    let forward_uri = format!("{}{}", address, _req.uri().path_and_query().map_or("", |x| x.as_str()));

    let _ = match filters.run(&_req.clone()).await {
        Ok(valid) => valid,
        Err(err) => {
            return err
        }
    };

    if let Ok(uri) = forward_uri.parse() {
        return send_request(uri, _req, payload).await;
    } else {
        return HttpResponse::NotFound().body("Invalid request URI");
    }
}

#[derive(Clone)]
struct APIGateway {
    filters: Arc<Filter>,
}

impl APIGateway {
    fn new() -> Self {
        dotenv().ok();

        let filters = Filter::new();
        filters.add(|req: HttpRequest| Box::pin(default_filter(req)));

        APIGateway {
            filters: Arc::new(filters),
        }
    }
    
    fn resource_service_uri(&self) -> Resource {
        return web::resource(r"/{service_uri:([a-zA-Z0-9._~:/?#@!$&'()*+,;=%-]*)?}")
                    .app_data(Data::new(Arc::clone(&self.filters.clone())))
                    .route(web::to(handle_request))
    }
}

#[derive(Deserialize, Debug)]
struct SiteverifyResponse {
    success: bool,
}

async fn recaptcha_siteverify(_req: HttpRequest) -> Result<(), HttpResponse> {
    let grr = _req.headers().get("x-g-recaptcha-response").expect("Some wrong").to_str().unwrap().to_string();
    let g_recaptcha_secret = std::env::var("G_RECAPTCHA_SECRET").expect("G_RECAPTCHA_SECRET must be set.");

    let params = [("response", grr), ("secret", g_recaptcha_secret)];
    let client = reqwest::Client::new();

    let res = client.post("https://www.google.com/recaptcha/api/siteverify")
                    .form(&params)
                    .send().await.unwrap().json::<SiteverifyResponse>().await.unwrap();

    if res.success {
        return Ok(())
    } else {
        return Err(HttpResponse::Unauthorized().body("Captcha hasn't validated"));
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let api_gateway = APIGateway::new();

    api_gateway.filters.add(|req: HttpRequest| Box::pin(recaptcha_siteverify(req)));
    
    let app = move || {
        App::new().service(api_gateway.resource_service_uri())
    };
    
    HttpServer::new(app)
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
