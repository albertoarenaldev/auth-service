package dev.albertoarenaldev.authservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.Executor;
import java.util.concurrent.ThreadPoolExecutor;

/**
 * Async execution configuration.
 *
 * <p>Activa el soporte de {@link org.springframework.scheduling.annotation.Async @Async}
 * y registra el pool dedicado {@code emailExecutor} usado para enviar
 * correos transaccionales fuera del thread del request HTTP.
 *
 * <p><b>Por que un pool dedicado y no el default de Spring:</b>
 * <ul>
 *   <li>Aisla la latencia de SMTP del resto de la aplicacion: un burst
 *       de envios no bloquea threads que atienden requests HTTP.</li>
 *   <li>Permite dimensionar el pool de forma especifica para I/O de
 *       red (SMTP), que pasa la mayor parte del tiempo bloqueado en
 *       IO frente a CPU.</li>
 *   <li>El thread name prefix {@code EmailSender-} facilita la
 *       observabilidad (stack traces, profilers, logs).</li>
 * </ul>
 *
 * <p><b>Por que {@link ThreadPoolExecutor.DiscardPolicy}:</b>
 * si el pool esta saturado (e.g. ataque DoS contra /forgot-password),
 * descartamos los envios en vez de ejecutar en el thread del request
 * ({@code CallerRunsPolicy}). Esto preserva la latencia del endpoint
 * (defensa contra DoS). El usuario puede repetir el request; el token
 * persistido en BD sigue siendo valido aunque el correo se haya
 * descartado.
 */
@Configuration
@EnableAsync
public class AsyncConfig {

    @Bean(name = "emailExecutor")
    public Executor emailExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(2);
        executor.setMaxPoolSize(10);
        executor.setQueueCapacity(500);
        executor.setThreadNamePrefix("EmailSender-");
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.DiscardPolicy());
        // Importante: el bean DEBE inicializarse explicitamente cuando se
        // registra programaticamente (no con @AsyncConfigurer). Si no, el
        // executor queda en estado no inicializado y los @Async caen al
        // default.
        executor.initialize();
        return executor;
    }
}
