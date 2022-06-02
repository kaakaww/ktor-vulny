package com.stackhawk

import io.ktor.server.engine.*
import io.ktor.server.netty.*
import com.stackhawk.plugins.*

fun main() {
    embeddedServer(Netty, port = 8080, host = "0.0.0.0") {
        configureSockets()
        configureRouting()
        configureSerialization()
        configureTemplating()
        configureHTTP()
        configureSecurity()
    }.start(wait = true)
}
