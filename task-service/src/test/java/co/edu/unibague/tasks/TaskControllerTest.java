package co.edu.unibague.tasks;

import com.jayway.jsonpath.JsonPath;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import java.util.UUID;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Pruebas de integración de task-service. El JWT se simula con spring-security-test
 * (no hace falta levantar auth-service); la base es H2 en memoria.
 */
@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:h2:mem:tasktest;DB_CLOSE_DELAY=-1",
        "spring.datasource.driver-class-name=org.h2.Driver",
        "spring.datasource.username=sa",
        "spring.datasource.password=",
        "spring.jpa.hibernate.ddl-auto=create-drop"
})
@AutoConfigureMockMvc
class TaskControllerTest {

    @Autowired
    MockMvc mvc;

    private static String uniqueUser() {
        return "user" + UUID.randomUUID().toString().substring(0, 8);
    }

    private static RequestPostProcessor asUser(String username) {
        return jwt().jwt(j -> j.subject(username)).authorities(new SimpleGrantedAuthority("ROLE_USER"));
    }

    private static RequestPostProcessor asAdmin(String username) {
        return jwt().jwt(j -> j.subject(username)).authorities(new SimpleGrantedAuthority("ROLE_ADMIN"));
    }

    private long createTask(String owner, String title) throws Exception {
        String body = mvc.perform(MockMvcRequestBuilders.post("/api/tasks")
                        .with(asUser(owner))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"title\":\"" + title + "\",\"description\":\"detalle\"}"))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        return ((Number) JsonPath.read(body, "$.id")).longValue();
    }

    @Test
    void requestWithoutTokenIsUnauthorized() throws Exception {
        mvc.perform(MockMvcRequestBuilders.get("/api/tasks")).andExpect(status().isUnauthorized());
    }

    @Test
    void postCreatesTaskOwnedByTokenSubject() throws Exception {
        String owner = uniqueUser();
        mvc.perform(MockMvcRequestBuilders.post("/api/tasks")
                        .with(asUser(owner))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"title\":\"Entregar proyecto\",\"description\":\"GitHub\"}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.title").value("Entregar proyecto"))
                .andExpect(jsonPath("$.completed").value(false))
                .andExpect(jsonPath("$.owner").value(owner));
    }

    @Test
    void postWithBlankTitleReturnsBadRequest() throws Exception {
        mvc.perform(MockMvcRequestBuilders.post("/api/tasks")
                        .with(asUser(uniqueUser()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"title\":\"\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void getListsOnlyOwnTasks() throws Exception {
        String ana = uniqueUser();
        String luis = uniqueUser();
        createTask(ana, "Tarea de Ana");
        createTask(luis, "Tarea de Luis");

        mvc.perform(MockMvcRequestBuilders.get("/api/tasks").with(asUser(ana)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].owner").value(ana));
    }

    @Test
    void getByIdOfAnotherUsersTaskReturnsNotFound() throws Exception {
        String ana = uniqueUser();
        long id = createTask(ana, "Privada");

        mvc.perform(MockMvcRequestBuilders.get("/api/tasks/" + id).with(asUser(uniqueUser())))
                .andExpect(status().isNotFound());
    }

    @Test
    void putUpdatesTask() throws Exception {
        String owner = uniqueUser();
        long id = createTask(owner, "Original");

        mvc.perform(MockMvcRequestBuilders.put("/api/tasks/" + id)
                        .with(asUser(owner))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"title\":\"Editada\",\"description\":\"listo\",\"completed\":true}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.title").value("Editada"))
                .andExpect(jsonPath("$.completed").value(true));
    }

    @Test
    void putOnAnotherUsersTaskReturnsNotFound() throws Exception {
        long id = createTask(uniqueUser(), "Ajena");

        mvc.perform(MockMvcRequestBuilders.put("/api/tasks/" + id)
                        .with(asUser(uniqueUser()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"title\":\"Hackeada\"}"))
                .andExpect(status().isNotFound());
    }

    @Test
    void deleteRemovesTask() throws Exception {
        String owner = uniqueUser();
        long id = createTask(owner, "Borrar");

        mvc.perform(MockMvcRequestBuilders.delete("/api/tasks/" + id).with(asUser(owner)))
                .andExpect(status().isNoContent());
        mvc.perform(MockMvcRequestBuilders.get("/api/tasks/" + id).with(asUser(owner)))
                .andExpect(status().isNotFound());
    }

    @Test
    void adminSeesAndCanDeleteAnyTask() throws Exception {
        String owner = uniqueUser();
        long id = createTask(owner, "De otro usuario");

        mvc.perform(MockMvcRequestBuilders.get("/api/tasks").with(asAdmin("admin")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.owner=='" + owner + "')]").isNotEmpty());
        mvc.perform(MockMvcRequestBuilders.delete("/api/tasks/" + id).with(asAdmin("admin")))
                .andExpect(status().isNoContent());
    }
}
